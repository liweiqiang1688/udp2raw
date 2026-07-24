#include "common.h"
#include "network.h"
#include "connection.h"
#include "misc.h"
#include "log.h"
#include "lib/md5.h"
#include "encrypt.h"
#include "fd_manager.h"
#include <algorithm>

#ifdef UDP2RAW_MP
u32_t detect_interval = 1500;
u64_t laste_detect_time = 0;

int use_udp_for_detection = 0;
int use_tcp_for_detection = 1;

extern pcap_t *pcap_handle;

extern int pcap_captured_full_len;
#endif

//————— client-side rotation state (anti traffic-policing) —————
static u64_t rotate_bytes_counter = 0;
static u64_t rotate_next_threshold = 0;
static u64_t rotate_last_time = 0;
static u64_t stall_win_start = 0;   // stall-detector window start (ms)
static u64_t stall_win_bytes = 0;   // uplink payload bytes inside the window
static void client_rotate_port(conn_info_t &conn_info, const char *reason);
static void start_preconnect(conn_info_t &active_conn, address_t target, int swap_requested);

// Mixed-family endpoint health. A failed family is cooled briefly while the
// active flow remains untouched; a successful authenticated heartbeat clears
// its penalty.
static const u64_t endpoint_health_timeout = 1800;  // three 600ms heartbeats
static const u64_t family_cooldown_base = 5000;
static u64_t family_cooldown_until[2] = {0, 0};
static int family_failures[2] = {0, 0};

static int family_slot(int family) {
    return family == AF_INET6 ? 1 : 0;
}

static void mark_family_success(int family) {
    int slot = family_slot(family);
    family_failures[slot] = 0;
    family_cooldown_until[slot] = 0;
}

static void mark_family_failure(int family) {
    int slot = family_slot(family);
    family_failures[slot] = std::min(family_failures[slot] + 1, 5);
    u64_t cooldown = family_cooldown_base << (family_failures[slot] - 1);
    if (cooldown > 60000) cooldown = 60000;
    family_cooldown_until[slot] = get_current_time() + cooldown;
    mylog(log_warn, "%s endpoint family cooling down for %llums after %d failure(s)\n",
          family == AF_INET6 ? "IPv6" : "IPv4",
          (unsigned long long)cooldown, family_failures[slot]);
}

static int select_client_family(int family) {
#ifdef UDP2RAW_LINUX
    if (rotate_endpoint_spec_cnt > 0)
        return use_listen_sock_for_family(family);
#endif
    raw_ip_version = family;
    return 0;
}

static int same_endpoint(address_t a, address_t b) {
    if (a.get_type() != b.get_type() || a.get_port() != b.get_port()) return 0;
    if (a.get_type() == AF_INET)
        return a.inner.ipv4.sin_addr.s_addr == b.inner.ipv4.sin_addr.s_addr;
    if (a.get_type() == AF_INET6)
        return memcmp(&a.inner.ipv6.sin6_addr, &b.inner.ipv6.sin6_addr,
                      sizeof(struct in6_addr)) == 0;
    return 0;
}

// Prefer the other address family for each hop. If it is cooling down or has
// no usable entry, stay within the active family. If every alternative is in
// cooldown, keep the active flow and let a later timer/rotation retry.
static int pick_next_endpoint(address_t active, address_t &picked) {
    if (rotate_endpoint_spec_cnt == 0) return -1;
    u64_t now = get_current_time();
    // Roll each spec's port exactly once and reuse it for both the exclusion
    // check and the final pick — rolling twice could select the very endpoint
    // the exclusion just rejected (active's own IP+port), which then makes
    // the preconnect indistinguishable from the active flow at the demux.
    // NB: sized by the endpoint pool cap, NOT MAX_LISTEN_SPECS — production
    // pools run 30+ specs and a 4-entry array segfaults on the first roll.
    int ports[MAX_ROTATE_ENDPOINT_SPECS];
    vector<int> preferred;
    vector<int> same_family;
    for (int i = 0; i < rotate_endpoint_spec_cnt; i++) {
        listen_spec_t &sp = rotate_endpoint_specs[i];
        int family = sp.addr.get_type();
        int port = sp.port_min;
        if (sp.port_max > sp.port_min)
            port += (int)(get_true_random_number() % (u64_t)(sp.port_max - sp.port_min + 1));
        ports[i] = port;
        address_t candidate = sp.addr;
        candidate.set_port(port);
        if (same_endpoint(candidate, active)) continue;
        if (family_cooldown_until[family_slot(family)] > now) {
            continue;
        } else if (family != (int)active.get_type()) {
            preferred.push_back(i);
        } else {
            same_family.push_back(i);
        }
    }
    vector<int> *pool = !preferred.empty() ? &preferred : &same_family;
    if (pool->empty()) return -1;
    int idx = (*pool)[get_true_random_number() % (u64_t)pool->size()];
    picked = rotate_endpoint_specs[idx].addr;
    picked.set_port(ports[idx]);
    return 0;
}

static int pick_rotation_endpoint(address_t active, address_t &picked) {
    if (rotate_endpoint_spec_cnt > 0)
        return pick_next_endpoint(active, picked);

    picked = active;
    int new_port = active.get_port();
    if (rotate_port_min > 0 && rotate_port_max > rotate_port_min) {
        int range = rotate_port_max - rotate_port_min + 1;
        while (new_port == (int)active.get_port())
            new_port = rotate_port_min + (int)(get_true_random_number() % (u64_t)range);
        picked.set_port(new_port);
    }
    if (rotate_dst_list[0] != 0 && active.get_type() == AF_INET6) {
        char buf[2000];
        snprintf(buf, sizeof(buf), "%s", rotate_dst_list);
        vector<string> candidates;
        char *save = nullptr;
        for (char *item = strtok_r(buf, ",", &save);
             item != nullptr;
             item = strtok_r(nullptr, ",", &save)) {
            if (strcmp(item, active.get_ip()) != 0)
                candidates.push_back(item);
        }
        if (!candidates.empty()) {
            const string &ip = candidates[get_true_random_number() % (u64_t)candidates.size()];
            char full[150];
            snprintf(full, sizeof(full), "[%s]:%d", ip.c_str(), new_port);
            picked.from_str(full);
        }
    }
    return same_endpoint(active, picked) ? -1 : 0;
}

static void set_active_endpoint(conn_info_t &conn_info, address_t endpoint) {
    remote_addr = endpoint;
    conn_info.raw_family = endpoint.get_type();
    select_client_family(conn_info.raw_family);
    conn_info.raw_info.send_info.new_dst_ip.from_address_t(endpoint);
    conn_info.raw_info.send_info.dst_port = endpoint.get_port();
}

//————— pre-connection state (make-before-break rotation) —————
struct preconnect_t {
    int active = 0;
    conn_info_t conn;          // second connection state machine
    int new_dst_port = 0;      // server port for packet classification
    address_t endpoint;
    int swap_requested = 0;
    int heartbeat_confirmed = 0;
    u64_t ready_time = 0;

    void reset() {
        active = 0;
        swap_requested = 0;
        heartbeat_confirmed = 0;
        ready_time = 0;
#ifdef UDP2RAW_LINUX
        client_standby_rule_del();
#endif
        // Free the old blob before re-init (blob is allocated per rotation).
        // conn_info_t's destructor would handle this, but we reuse the struct.
        if (conn.blob) { delete conn.blob; conn.blob = nullptr; }
        conn.re_init();
    }
} pre;

static void fail_preconnect(conn_info_t &active_conn, const char *reason) {
    mylog(log_warn, "%s; keeping active flow\n", reason);
    int failed_family = pre.conn.raw_family;
    int wanted_swap = pre.swap_requested;
#ifdef UDP2RAW_LINUX
    client_discard_v6_preconnect(active_conn.raw_info.send_info.new_src_ip,
                                 active_conn.raw_family);
#endif
    mark_family_failure(failed_family);
    pre.reset();
    select_client_family(active_conn.raw_family);
#ifdef UDP2RAW_LINUX
    if (!disable_bpf_filter)
        init_filter(active_conn.raw_info.send_info.src_port);
#endif
    if (wanted_swap) {
        address_t retry;
        address_t active_remote;
        active_remote.from_ip_port_new(active_conn.raw_family,
            active_conn.raw_family == AF_INET
                ? (void *)&active_conn.raw_info.send_info.new_dst_ip.v4
                : (void *)&active_conn.raw_info.send_info.new_dst_ip.v6,
            active_conn.raw_info.send_info.dst_port);
        if (pick_rotation_endpoint(active_remote, retry) == 0)
            start_preconnect(active_conn, retry, 1);
    }
}

static void fail_active_endpoint(conn_info_t &conn_info) {
    int failed_family = conn_info.raw_family;
    mark_family_failure(failed_family);
    if (pre.active) {
#ifdef UDP2RAW_LINUX
        select_client_family(pre.conn.raw_family);
        client_discard_v6_preconnect(conn_info.raw_info.send_info.new_src_ip,
                                     conn_info.raw_family);
#endif
        pre.reset();
    }
    address_t next;
    if (pick_rotation_endpoint(remote_addr, next) == 0) {
        mylog(log_warn, "active endpoint failed; reconnecting via %s\n", next.get_str());
        set_active_endpoint(conn_info, next);
    } else {
        select_client_family(conn_info.raw_family);
    }
}

static void pre_send_syn(conn_info_t &pc) {
    if (select_client_family(pc.raw_family) != 0) return;
    packet_info_t &send_info = pc.raw_info.send_info;
    if (pc.last_hb_sent_time == 0) {
        send_info.psh = 0;
        send_info.syn = 1;
        send_info.ack = 0;
        send_info.ts_ack = 0;
        send_info.seq = get_true_random_number();
        send_info.ack_seq = get_true_random_number();
    }
    send_raw0(pc.raw_info, 0, 0);
    pc.last_hb_sent_time = get_current_time();
}

static void pre_send_handshake1(conn_info_t &pc) {
    if (select_client_family(pc.raw_family) != 0) return;
    packet_info_t &send_info = pc.raw_info.send_info;
    packet_info_t &recv_info = pc.raw_info.recv_info;
    if (raw_mode == mode_faketcp) {
        if (pc.last_hb_sent_time == 0) {
            send_info.seq++;
            send_info.ack_seq = recv_info.seq + 1;
            send_info.ts_ack = recv_info.ts;
            pc.raw_info.reserved_send_seq = send_info.seq;
        }
        send_info.seq = pc.raw_info.reserved_send_seq;
        send_info.psh = 0;
        send_info.syn = 0;
        send_info.ack = 1;
        send_raw0(pc.raw_info, 0, 0);
        send_handshake(pc.raw_info, pc.my_id, 0, pc.local_const_id);
        send_info.seq += pc.raw_info.send_info.data_len;
    } else {
        send_handshake(pc.raw_info, pc.my_id, 0, pc.local_const_id);
        if (raw_mode == mode_icmp)
            send_info.my_icmp_seq++;
    }
    pc.last_hb_sent_time = get_current_time();
}

static void pre_send_handshake2(conn_info_t &pc) {
    if (select_client_family(pc.raw_family) != 0) return;
    packet_info_t &send_info = pc.raw_info.send_info;
    packet_info_t &recv_info = pc.raw_info.recv_info;
    if (raw_mode == mode_faketcp) {
        if (pc.last_hb_sent_time == 0) {
            send_info.ack_seq = recv_info.seq + pc.raw_info.recv_info.data_len;
            send_info.ts_ack = recv_info.ts;
            pc.raw_info.reserved_send_seq = send_info.seq;
        }
        send_info.seq = pc.raw_info.reserved_send_seq;
        send_handshake(pc.raw_info, pc.my_id, pc.oppsite_id, pc.local_const_id);
        send_info.seq += pc.raw_info.send_info.data_len;
    } else {
        send_handshake(pc.raw_info, pc.my_id, pc.oppsite_id, pc.local_const_id);
        if (raw_mode == mode_icmp)
            send_info.my_icmp_seq++;
    }
    pc.last_hb_sent_time = get_current_time();
}

int client_on_timer(conn_info_t &conn_info)  // for client. called when a timer is ready in epoll
{
    if (conn_info.raw_family != AF_INET && conn_info.raw_family != AF_INET6)
        conn_info.raw_family = remote_addr.get_type();
    packet_info_t &send_info = conn_info.raw_info.send_info;
    packet_info_t &recv_info = conn_info.raw_info.recv_info;

    // Progress the predictive connection independently of the active flow.
    // This must run before the active-state branches below, which return after
    // handling their own timer event.
    if (pre.active) {
        conn_info_t &pc = pre.conn;
        u64_t now = get_current_time();
        if ((pc.state.client_current_state == client_tcp_handshake
            || pc.state.client_current_state == client_handshake1
             || pc.state.client_current_state == client_handshake2)
            && now - pc.last_state_time > client_handshake_timeout) {
            fail_preconnect(conn_info, "preconnect handshake timed out");
        } else if (pc.state.client_current_state == client_tcp_handshake) {
            if (now - pc.last_hb_sent_time > client_retry_interval)
                pre_send_syn(pc);
        } else if (pc.state.client_current_state == client_handshake1) {
            if (get_current_time() - pc.last_hb_sent_time > client_retry_interval) {
                pre_send_handshake1(pc);
            }
        } else if (pc.state.client_current_state == client_handshake2) {
            if (get_current_time() - pc.last_hb_sent_time > client_retry_interval) {
                pre_send_handshake2(pc);
            }
        } else if (pc.state.client_current_state == client_ready
                   && !pre.heartbeat_confirmed
                   && now - pre.ready_time > endpoint_health_timeout) {
            fail_preconnect(conn_info, "preconnect heartbeat qualification timed out");
        } else if (pc.state.client_current_state == client_ready
                   && pre.heartbeat_confirmed
                   && now - pc.last_hb_recv_time > client_conn_timeout) {
            fail_preconnect(conn_info, "preconnect heartbeat expired");
        } else if (pc.state.client_current_state == client_ready
                   && now - pc.last_hb_sent_time >= heartbeat_interval) {
            select_client_family(pc.raw_family);
            if (hb_mode == 0)
                send_safer(pc, 'h', hb_buf, 0);
            else
                send_safer(pc, 'h', hb_buf, hb_len);
            pc.last_hb_sent_time = now;
        }
    }
    select_client_family(conn_info.raw_family);
    raw_info_t &raw_info = conn_info.raw_info;
    conn_info.blob->conv_manager.c.clear_inactive();
    mylog(log_trace, "timer!\n");

    mylog(log_trace, "roller my %d,oppsite %d,%lld\n", int(conn_info.my_roller), int(conn_info.oppsite_roller), conn_info.last_oppsite_roller_time);

    mylog(log_trace, "<client_on_timer,send_info.ts_ack= %u>\n", send_info.ts_ack);

#ifdef UDP2RAW_MP
    // mylog(log_debug,"pcap cnt :%d\n",pcap_cnt);
    if (send_with_pcap && !pcap_header_captured) {
        if (get_current_time() - laste_detect_time > detect_interval) {
            laste_detect_time = get_current_time();
        } else {
            return 0;
        }
        /*
                        struct sockaddr_in remote_addr_in={0};

                        socklen_t slen = sizeof(sockaddr_in);
                        int port=get_true_random_number()%65534+1;
                        remote_addr_in.sin_family = AF_INET;
                        remote_addr_in.sin_port = htons(port);
                        remote_addr_in.sin_addr.s_addr = remote_ip_uint32;*/
        int port = get_true_random_number() % 65534 + 1;
        address_t tmp_addr = remote_addr;
        tmp_addr.set_port(port);

        if (use_udp_for_detection) {
            int new_udp_fd = socket(tmp_addr.get_type(), SOCK_DGRAM, IPPROTO_UDP);
            if (new_udp_fd < 0) {
                mylog(log_warn, "create new_udp_fd error\n");
                return -1;
            }
            setnonblocking(new_udp_fd);
            u64_t tmp = get_true_random_number();

            int ret = sendto(new_udp_fd, (char *)(&tmp), sizeof(tmp), 0, (struct sockaddr *)&tmp_addr.inner, tmp_addr.get_len());
            if (ret == -1) {
                mylog(log_warn, "sendto() failed\n");
            }
            sock_close(new_udp_fd);
        }

        if (use_tcp_for_detection) {
            static int last_tcp_fd = -1;

            int new_tcp_fd = socket(tmp_addr.get_type(), SOCK_STREAM, IPPROTO_TCP);
            if (new_tcp_fd < 0) {
                mylog(log_warn, "create new_tcp_fd error\n");
                return -1;
            }
            setnonblocking(new_tcp_fd);
            connect(new_tcp_fd, (struct sockaddr *)&tmp_addr.inner, tmp_addr.get_len());
            if (last_tcp_fd != -1)
                sock_close(last_tcp_fd);
            last_tcp_fd = new_tcp_fd;
            // close(new_tcp_fd);
        }

        mylog(log_info, "waiting for a use-able packet to be captured\n");

        return 0;
    }
#endif
    if (raw_info.disabled) {
        conn_info.state.client_current_state = client_idle;
        conn_info.my_id = get_true_random_number_nz();
        // The standby was built against the old connection context — drop it
        // rather than letting it stall against a re-handshaking active flow.
        if (pre.active) pre.reset();

        mylog(log_info, "state back to client_idle\n");
    }

    if (conn_info.state.client_current_state == client_idle) {
        raw_info.rst_received = 0;
        raw_info.disabled = 0;

        fail_time_counter++;
        if (max_fail_time > 0 && fail_time_counter > max_fail_time) {
            mylog(log_fatal, "max_fail_time exceed\n");
            myexit(-1);
        }

        conn_info.blob->anti_replay.re_init();
        conn_info.my_id = get_true_random_number_nz();  /// todo no need to do this everytime

        address_t tmp_addr;
        // u32_t new_ip=0;
        if (!force_source_ip || source_addr.get_type() != remote_addr.get_type()) {
            if (get_src_adress2(tmp_addr, remote_addr) != 0) {
                mylog(log_warn, "get_src_adress() failed\n");
                return -1;
            }
            // source_addr=new_addr;
            // source_addr.set_port(0);

            mylog(log_info, "source_addr is now %s\n", tmp_addr.get_ip());

            /*
            if(new_ip!=source_ip_uint32)
            {
                    mylog(log_info,"source ip changed from %s to ",my_ntoa(source_ip_uint32));
                    log_bare(log_info,"%s\n",my_ntoa(new_ip));
                    source_ip_uint32=new_ip;
                    send_info.src_ip=new_ip;
            }*/

        } else {
            tmp_addr = source_addr;
        }

        send_info.new_src_ip.from_address_t(tmp_addr);

        if (force_source_port == 0) {
            send_info.src_port = client_bind_to_a_new_port2(bind_fd, tmp_addr);
        } else {
            send_info.src_port = source_port;
        }

        if (raw_mode == mode_icmp) {
            send_info.dst_port = send_info.src_port;
        }

        mylog(log_info, "using port %d\n", send_info.src_port);
        init_filter(send_info.src_port);

        if (raw_mode == mode_icmp || raw_mode == mode_udp) {
            conn_info.state.client_current_state = client_handshake1;

            mylog(log_info, "state changed from client_idle to client_pre_handshake\n");
        }
        if (raw_mode == mode_faketcp) {
            if (use_tcp_dummy_socket) {
                setnonblocking(bind_fd);
                int ret = connect(bind_fd, (struct sockaddr *)&remote_addr.inner, remote_addr.get_len());
                mylog(log_debug, "ret=%d,errno=%s, %d %s\n", ret, get_sock_error(), bind_fd, remote_addr.get_str());
                // mylog(log_info,"ret=%d,errno=,%d %s\n",ret,bind_fd,remote_addr.get_str());
                conn_info.state.client_current_state = client_tcp_handshake_dummy;
                mylog(log_info, "state changed from client_idle to client_tcp_handshake_dummy\n");
            } else {
                conn_info.state.client_current_state = client_tcp_handshake;
                mylog(log_info, "state changed from client_idle to client_tcp_handshake\n");
            }
        }
        conn_info.last_state_time = get_current_time();
        conn_info.last_hb_sent_time = 0;
        // dont return;
    }
    if (conn_info.state.client_current_state == client_tcp_handshake)  // send and resend syn
    {
        assert(raw_mode == mode_faketcp);
        if (get_current_time() - conn_info.last_state_time > client_handshake_timeout) {
            conn_info.state.client_current_state = client_idle;
            fail_active_endpoint(conn_info);
            mylog(log_info, "state back to client_idle from client_tcp_handshake\n");
            return 0;

        } else if (get_current_time() - conn_info.last_hb_sent_time > client_retry_interval) {
            if (raw_mode == mode_faketcp) {
                if (conn_info.last_hb_sent_time == 0) {
                    send_info.psh = 0;
                    send_info.syn = 1;
                    send_info.ack = 0;
                    send_info.ts_ack = 0;
                    send_info.seq = get_true_random_number();
                    send_info.ack_seq = get_true_random_number();
                }
            }

            send_raw0(raw_info, 0, 0);

            conn_info.last_hb_sent_time = get_current_time();
            mylog(log_info, "(re)sent tcp syn\n");
            return 0;
        } else {
            return 0;
        }
        return 0;
    } else if (conn_info.state.client_current_state == client_tcp_handshake_dummy) {
        assert(raw_mode == mode_faketcp);
        if (get_current_time() - conn_info.last_state_time > client_handshake_timeout) {
            conn_info.state.client_current_state = client_idle;
            fail_active_endpoint(conn_info);
            mylog(log_info, "state back to client_idle from client_tcp_handshake_dummy\n");
            return 0;
        }
    } else if (conn_info.state.client_current_state == client_handshake1)  // send and resend handshake1
    {
        if (get_current_time() - conn_info.last_state_time > client_handshake_timeout) {
            conn_info.state.client_current_state = client_idle;
            fail_active_endpoint(conn_info);
            mylog(log_info, "state back to client_idle from client_handshake1\n");
            return 0;

        } else if (get_current_time() - conn_info.last_hb_sent_time > client_retry_interval) {
            if (raw_mode == mode_faketcp) {
                if (conn_info.last_hb_sent_time == 0) {
                    send_info.seq++;
                    send_info.ack_seq = recv_info.seq + 1;
                    send_info.ts_ack = recv_info.ts;
                    raw_info.reserved_send_seq = send_info.seq;
                }
                send_info.seq = raw_info.reserved_send_seq;
                send_info.psh = 0;
                send_info.syn = 0;
                send_info.ack = 1;

                if (!use_tcp_dummy_socket)
                    send_raw0(raw_info, 0, 0);

                send_handshake(raw_info, conn_info.my_id, 0, conn_info.local_const_id);

                send_info.seq += raw_info.send_info.data_len;
            } else {
                send_handshake(raw_info, conn_info.my_id, 0, conn_info.local_const_id);
                if (raw_mode == mode_icmp)
                    send_info.my_icmp_seq++;
            }

            conn_info.last_hb_sent_time = get_current_time();
            mylog(log_info, "(re)sent handshake1\n");
            return 0;
        } else {
            return 0;
        }
        return 0;
    } else if (conn_info.state.client_current_state == client_handshake2) {
        if (get_current_time() - conn_info.last_state_time > client_handshake_timeout) {
            conn_info.state.client_current_state = client_idle;
            fail_active_endpoint(conn_info);
            mylog(log_info, "state back to client_idle from client_handshake2\n");
            return 0;
        } else if (get_current_time() - conn_info.last_hb_sent_time > client_retry_interval) {
            if (raw_mode == mode_faketcp) {
                if (conn_info.last_hb_sent_time == 0) {
                    send_info.ack_seq = recv_info.seq + raw_info.recv_info.data_len;
                    send_info.ts_ack = recv_info.ts;
                    raw_info.reserved_send_seq = send_info.seq;
                }
                send_info.seq = raw_info.reserved_send_seq;
                send_handshake(raw_info, conn_info.my_id, conn_info.oppsite_id,
                               conn_info.local_const_id);
                send_info.seq += raw_info.send_info.data_len;

            } else {
                send_handshake(raw_info, conn_info.my_id, conn_info.oppsite_id,
                               conn_info.local_const_id);
                if (raw_mode == mode_icmp)
                    send_info.my_icmp_seq++;
            }
            conn_info.last_hb_sent_time = get_current_time();
            mylog(log_info, "(re)sent handshake2\n");
            return 0;

        } else {
            return 0;
        }
        return 0;
    } else if (conn_info.state.client_current_state == client_ready) {
        fail_time_counter = 0;
        mylog(log_trace, "time %llu,%llu\n", get_current_time(), conn_info.last_state_time);

#ifdef UDP2RAW_LINUX
        // Stall detector: a clamp-to-zero fuse produces no bytes, so the
        // --rotate-bytes trigger never fires and the flow stalls forever.
        // Heartbeats alone stay far below 64KB per window; a starved upper
        // layer (TCP retransmits/ACKs) also stops arriving — either way,
        // tiny uplink volume for --rotate-stall seconds means this flow is
        // dead weight: rotate out of it.
        if (rotate_bytes > 0 && rotate_stall > 0) {
            u64_t now_ms = get_current_time();
            if (stall_win_start == 0) stall_win_start = now_ms;
            if (now_ms - stall_win_start >= (u64_t)rotate_stall * 1000) {
                if (stall_win_bytes < 65536 && now_ms - rotate_last_time >= (u64_t)rotate_min_interval * 1000) {
                    client_rotate_port(conn_info, "stall detected");
                }
                stall_win_start = now_ms;
                stall_win_bytes = 0;
            }
        }
#endif

        if (get_current_time() - conn_info.last_hb_recv_time > client_conn_timeout) {
            conn_info.state.client_current_state = client_idle;
            conn_info.my_id = get_true_random_number_nz();
            fail_active_endpoint(conn_info);
            mylog(log_info, "state back to client_idle from  client_ready bc of server-->client direction timeout\n");
            return 0;
        }

        if (get_current_time() - conn_info.last_oppsite_roller_time > client_conn_uplink_timeout) {
            conn_info.state.client_current_state = client_idle;
            conn_info.my_id = get_true_random_number_nz();
            fail_active_endpoint(conn_info);
            mylog(log_info, "state back to client_idle from  client_ready bc of client-->server direction timeout\n");
            return 0;
        }

        if (get_current_time() - conn_info.last_hb_sent_time < heartbeat_interval) {
            return 0;
        }

        mylog(log_debug, "heartbeat sent <%x,%x>\n", conn_info.oppsite_id, conn_info.my_id);

        if (hb_mode == 0)
            send_safer(conn_info, 'h', hb_buf, 0);  /////////////send
        else
            send_safer(conn_info, 'h', hb_buf, hb_len);
        conn_info.last_hb_sent_time = get_current_time();
        return 0;
    } else {
        mylog(log_fatal, "unknown state,this shouldnt happen.\n");
        myexit(-1);
    }

    return 0;
}

//————— client-side remote-port rotation (anti traffic-policing) —————
// A single outer flow gets throttled/reset by the ISP after it accumulates
// some volume (measured: ~150-700MB at full speed). Rotate to a fresh 5-tuple
// (new source port + new remote port from --rotate-ports) *before* that
// happens. The reconnect goes through the normal client_idle path, so the
// blip is the same as a routine reconnect (~1-2 RTTs, covered by upper-layer
// FEC/retransmits).
static u64_t rotate_pick_threshold() {
    u64_t base = rotate_bytes;
    if (base == 0) return 1;
    if (rotate_jitter > 0) {
        int span = 2 * rotate_jitter + 1;
        int pct = 100 - rotate_jitter + (int)(get_true_random_number() % (u64_t)span);
        base = base * (u64_t)pct / 100;
    }
    return base == 0 ? 1 : base;
}

// Start a background preconnect to `new_port`.  Called after each swap so
// the next rotation finds a client_ready connection — instant swap.
// Both old and new v6 source addresses coexist (deferred deletion), so
// the preconnect socket stays valid across v6 rotations.
static void start_preconnect(conn_info_t &active_conn, address_t target, int swap_requested) {
    pre.reset();

    pre.endpoint = target;
    pre.new_dst_port = target.get_port();
    pre.swap_requested = swap_requested;

    pre.conn.re_init();
    pre.conn.prepare();
    pre.conn.my_id = get_true_random_number_nz();
    pre.conn.local_const_id = get_true_random_number_nz();
    pre.conn.raw_family = target.get_type();

    if (select_client_family(pre.conn.raw_family) != 0) {
        mylog(log_warn, "no raw socket context for preconnect family\n");
        mark_family_failure(pre.conn.raw_family);
        pre.reset();
        select_client_family(active_conn.raw_family);
        return;
    }
    // `pre` has static storage duration, so its packet_info_t members were
    // originally constructed before command-line parsing selected raw_mode.
    // Reconstruct them here with the pending family's current protocol;
    // otherwise a UDP standby can accidentally carry an IPv4/IPv6 header
    // marked as TCP and never reach the matching server listener.
    pre.conn.raw_info = raw_info_t();

#ifdef UDP2RAW_LINUX
    if (target.get_type() == AF_INET6
        && rotate_v6_prefix[0] != 0 && rotate_v6_dev[0] != 0) {
        address_t saved_remote = remote_addr;
        remote_addr = target;
        client_rotate_v6_source();
        remote_addr = saved_remote;
    }
#endif

    packet_info_t &p_send = pre.conn.raw_info.send_info;
    p_send.new_dst_ip.from_address_t(target);
    p_send.dst_port = target.get_port();
    {
        address_t tmp_src;
        if (force_source_ip && source_addr.get_type() == target.get_type())
            tmp_src = source_addr;
        else if (get_src_adress2(tmp_src, target) != 0) {
#ifdef UDP2RAW_LINUX
            select_client_family(pre.conn.raw_family);
            client_discard_v6_preconnect(active_conn.raw_info.send_info.new_src_ip,
                                         active_conn.raw_family);
#endif
            mark_family_failure(pre.conn.raw_family);
            pre.reset();
#ifdef UDP2RAW_LINUX
            select_client_family(active_conn.raw_family);
            if (!disable_bpf_filter)
                init_filter(active_conn.raw_info.send_info.src_port);
#endif
            return;
        }
        p_send.new_src_ip.from_address_t(tmp_src);
        if (force_source_port == 0)
            p_send.src_port = client_bind_to_a_new_port2(bind_fd, tmp_src);
        else
            p_send.src_port = source_port;
    }

    if (raw_mode == mode_faketcp && use_tcp_dummy_socket) {
        mylog(log_warn, "preconnect disabled for --easy-faketcp; using normal reconnect\n");
#ifdef UDP2RAW_LINUX
        client_discard_v6_preconnect(active_conn.raw_info.send_info.new_src_ip,
                                     active_conn.raw_family);
#endif
        pre.reset();
#ifdef UDP2RAW_LINUX
        select_client_family(active_conn.raw_family);
        if (!disable_bpf_filter)
            init_filter(active_conn.raw_info.send_info.src_port);
#endif
        return;
    }

    if (raw_mode == mode_faketcp) {
        pre.conn.state.client_current_state = client_tcp_handshake;
        pre.conn.raw_info.send_info.psh = 0;
        pre.conn.raw_info.send_info.syn = 1;
        pre.conn.raw_info.send_info.ack = 0;
        pre.conn.raw_info.send_info.ts_ack = 0;
    } else {
        pre.conn.state.client_current_state = client_handshake1;
    }
    pre.conn.last_state_time = get_current_time();
    pre.conn.last_hb_sent_time = 0;
#ifdef UDP2RAW_LINUX
    if (!disable_bpf_filter) {
        int active_port = active_conn.raw_info.send_info.src_port;
        int pending_port = p_send.src_port;
        int filter_min = pending_port;
        int filter_max = pending_port;
        if (active_conn.raw_family == pre.conn.raw_family) {
            filter_min = std::min(active_port, pending_port);
            filter_max = std::max(active_port, pending_port);
        }
        if (attach_range_filter(raw_recv_fd, pre.conn.raw_family,
                                filter_min, filter_max) != 0) {
            client_discard_v6_preconnect(active_conn.raw_info.send_info.new_src_ip,
                                         active_conn.raw_family);
            mark_family_failure(pre.conn.raw_family);
            pre.reset();
            select_client_family(active_conn.raw_family);
            init_filter(active_port);
            return;
        }
        if (active_conn.raw_family != pre.conn.raw_family) {
            select_client_family(active_conn.raw_family);
            init_filter(active_port);
            select_client_family(pre.conn.raw_family);
        }
    }
#endif
    pre.active = 1;
#ifdef UDP2RAW_LINUX
    // The -a rule covers only the ACTIVE remote — give the standby its own
    // drop rule or the kernel RSTs/ICMP-rejects its handshake from the server.
    client_standby_rule_add(target.get_ip(), target.get_type(), target.get_port());
#endif
    char pre_src[100], pre_dst[100];
    snprintf(pre_src, sizeof(pre_src), "%s", p_send.new_src_ip.get_str1());
    snprintf(pre_dst, sizeof(pre_dst), "%s", p_send.new_dst_ip.get_str2());
    mylog(log_info, "preconnect started: family=%s src=%s:%d endpoint=%s:%d swap_requested=%d\n",
          pre.conn.raw_family == AF_INET6 ? "IPv6" : "IPv4",
          pre_src, p_send.src_port, pre_dst, p_send.dst_port, swap_requested);
    if (raw_mode == mode_faketcp)
        pre_send_syn(pre.conn);
    else
        pre_send_handshake1(pre.conn);
    select_client_family(active_conn.raw_family);
}

// Promote a completed preconnect to the active raw connection. The local UDP
// listener (udp_fd) belongs to tinyvpn and must never be swapped: preconnect
// only changes the raw packet state and the reserved source port.
static void swap_preconnect(conn_info_t &conn_info) {
    if (!pre.active || pre.conn.state.client_current_state != client_ready
        || !pre.heartbeat_confirmed)
        return;

    const int new_port = pre.conn.raw_info.send_info.dst_port;
    const int new_family = pre.conn.raw_family;
    address_t pre_remote = pre.endpoint;
    remote_addr = pre_remote;

    conn_info.my_id = pre.conn.my_id;
    conn_info.oppsite_id = pre.conn.oppsite_id;
    conn_info.local_const_id = pre.conn.local_const_id;
    conn_info.raw_family = new_family;
    memcpy(&conn_info.raw_info.send_info, &pre.conn.raw_info.send_info, sizeof(packet_info_t));
    memcpy(&conn_info.raw_info.recv_info, &pre.conn.raw_info.recv_info, sizeof(packet_info_t));
    conn_info.state.client_current_state = client_ready;
    conn_info.last_hb_recv_time = get_current_time();
    conn_info.last_hb_sent_time = 0;
    conn_info.last_oppsite_roller_time = conn_info.last_hb_recv_time;

#ifdef UDP2RAW_LINUX
    // Conv pre-sync: replay every active conv through the qualified standby so
    // the server pre-creates the same ids on the new connection, and carry the
    // table over into the promoted blob so the same ids keep being used.
    // Without this, downlink streams only resume after each conv's first
    // uplink packet registers server-side — an uplink+RTT gap that TCP's RTO
    // backoff amplifies into seconds of stall on every rotation.
    if (conn_info.blob && pre.conn.blob) {
        select_client_family(pre.conn.raw_family);
        char zero = 0;
        for (auto &kv : conn_info.blob->conv_manager.c.conv_to_data)
            send_data_safer(pre.conn, &zero, 1, kv.first);
        for (auto &kv : conn_info.blob->conv_manager.c.conv_to_data)
            pre.conn.blob->conv_manager.c.insert_conv(kv.first, kv.second);
        select_client_family(conn_info.raw_family);
    }
#endif

    blob_t *old_blob = conn_info.blob;
    conn_info.blob = pre.conn.blob;
    pre.conn.blob = nullptr;
    delete old_blob;
    pre.reset();
    select_client_family(conn_info.raw_family);
    mark_family_success(conn_info.raw_family);

#ifdef UDP2RAW_LINUX
    if (conn_info.raw_family == AF_INET6)
        deferred_v6_cleanup();  // old source address is no longer needed
    if (!disable_bpf_filter)
        init_filter(conn_info.raw_info.send_info.src_port);
    client_rotate_iptables_rule(new_port);
#endif
    mylog(log_info, "preconnect swap: active raw flow is now %s:%d\n",
          remote_addr.get_ip(), new_port);

    // Prepare the following destination while keeping remote_addr aligned
    // with the newly active flow after start_preconnect() returns.
    address_t next_endpoint;
    if (pick_rotation_endpoint(remote_addr, next_endpoint) == 0)
        start_preconnect(conn_info, next_endpoint, 0);
}

static void client_rotate_port(conn_info_t &conn_info, const char *reason) {
    u64_t rotated_bytes = rotate_bytes_counter;
    rotate_bytes_counter = 0;
    rotate_next_threshold = rotate_pick_threshold();
    rotate_last_time = get_current_time();
    stall_win_start = 0;
    stall_win_bytes = 0;

    address_t target;
    if (pre.active) {
        target = pre.endpoint;
    } else if (pick_rotation_endpoint(remote_addr, target) != 0) {
        mylog(log_warn, "rotation requested but no alternate healthy endpoint is available\n");
        return;
    }

    char active_text[150], target_text[150];
    snprintf(active_text, sizeof(active_text), "%s", remote_addr.get_str());
    snprintf(target_text, sizeof(target_text), "%s", target.get_str());
    mylog(log_info, "transport rotation (%s): remote %s -> %s after %llu payload bytes, next threshold %llu\n",
          reason, active_text, target_text,
          (unsigned long long)rotated_bytes,
          (unsigned long long)rotate_next_threshold);
    char src_ip[100], dst_ip[100];
    snprintf(src_ip, sizeof(src_ip), "%s", force_source_ip ? source_addr.get_ip() : local_addr.get_ip());
    snprintf(dst_ip, sizeof(dst_ip), "%s", target.get_ip());
    mylog(log_info, "  rotation 5-tuple: src=%s:%d  dst=%s:%d\n",
          src_ip, conn_info.raw_info.send_info.src_port,
          dst_ip, target.get_port());

    // Predictive preconnect: if a preconnect is already client_ready
    // and heartbeat-qualified, swap instantly. Otherwise flag it for
    // promotion as soon as its first authenticated heartbeat returns.
    if (pre.active && pre.conn.state.client_current_state == client_ready
        && pre.heartbeat_confirmed) {
        swap_preconnect(conn_info);
    } else if (pre.active) {
        pre.swap_requested = 1;
        mylog(log_info, "preconnect not yet healthy; keeping active connection\n");
    } else {
        if (raw_mode == mode_icmp || (raw_mode == mode_faketcp && use_tcp_dummy_socket)) {
            // ICMP has no port to classify, and easy-faketcp owns one
            // connected TCP dummy socket. Fall back to the normal reconnect
            // path rather than silently leaving the old flow active forever.
            pre.reset();
            remote_addr = target;
            conn_info.raw_family = target.get_type();
            select_client_family(conn_info.raw_family);
#ifdef UDP2RAW_LINUX
            if (!disable_bpf_filter)
                init_filter(conn_info.raw_info.send_info.src_port);
#endif
            conn_info.state.client_current_state = client_idle;
            conn_info.my_id = get_true_random_number_nz();
            client_on_timer(conn_info);
            client_on_timer(conn_info);
            return;
        }
        start_preconnect(conn_info, target, 1);
    }
}

static void client_rotate_account(conn_info_t &conn_info, int payload_bytes) {
    if (rotate_bytes == 0) return;
    if (conn_info.state.client_current_state != client_ready) return;
    rotate_bytes_counter += (u64_t)payload_bytes;

    u64_t elapsed = get_current_time() - rotate_last_time;
    int max_seconds = rotate_max_interval > 0 ? rotate_max_interval : rotate_min_interval;  // fallback: use min as max when unset
    int time_triggered = (rotate_max_interval > 0 && elapsed >= (u64_t)max_seconds * 1000);
    int bytes_triggered = (rotate_bytes_counter >= rotate_next_threshold && elapsed >= (u64_t)rotate_min_interval * 1000);

    if (!time_triggered && !bytes_triggered) return;

    client_rotate_port(conn_info, bytes_triggered ? "bytes threshold" : "max interval");
}

int client_on_raw_recv_hs2_or_ready(conn_info_t &conn_info, char type, char *data, int data_len) {
    packet_info_t &send_info = conn_info.raw_info.send_info;
    packet_info_t &recv_info = conn_info.raw_info.recv_info;

    if (!recv_info.new_src_ip.equal(send_info.new_dst_ip) || recv_info.src_port != send_info.dst_port) {
        mylog(log_warn, "unexpected adress %s %s %d %d,this shouldnt happen.\n", recv_info.new_src_ip.get_str1(), send_info.new_dst_ip.get_str2(), recv_info.src_port, send_info.dst_port);
        return -1;
    }

    if (conn_info.state.client_current_state == client_handshake2) {
        mylog(log_info, "changed state from to client_handshake2 to client_ready\n");
        conn_info.state.client_current_state = client_ready;
        conn_info.last_hb_sent_time = 0;
        conn_info.last_hb_recv_time = get_current_time();
        conn_info.last_oppsite_roller_time = conn_info.last_hb_recv_time;
        mark_family_success(conn_info.raw_family);
        client_on_timer(conn_info);
        if (!pre.active) {
            address_t next_endpoint;
            if (pick_rotation_endpoint(remote_addr, next_endpoint) == 0)
                start_preconnect(conn_info, next_endpoint, 0);
        }
    }
    if (data_len >= 0 && type == 'h') {
        mylog(log_debug, "[hb]heart beat received,oppsite_roller=%d\n", int(conn_info.oppsite_roller));
        conn_info.last_hb_recv_time = get_current_time();
        return 0;
    } else if (data_len >= int(sizeof(u32_t)) && type == 'd') {
        mylog(log_trace, "received a data from fake tcp,len:%d\n", data_len);

        if (hb_mode == 0)
            conn_info.last_hb_recv_time = get_current_time();

        u32_t tmp_conv_id;
        memcpy(&tmp_conv_id, &data[0], sizeof(tmp_conv_id));
        tmp_conv_id = ntohl(tmp_conv_id);

        if (!conn_info.blob->conv_manager.c.is_conv_used(tmp_conv_id)) {
            mylog(log_info, "unknow conv %d,ignore\n", tmp_conv_id);
            return 0;
        }

        conn_info.blob->conv_manager.c.update_active_time(tmp_conv_id);

        // u64_t u64=conn_info.blob->conv_manager.c.find_data_by_conv(tmp_conv_id);
        address_t tmp_addr = conn_info.blob->conv_manager.c.find_data_by_conv(tmp_conv_id);

        // sockaddr_in tmp_sockaddr={0};

        // tmp_sockaddr.sin_family = AF_INET;
        // tmp_sockaddr.sin_addr.s_addr=(u64>>32u);

        // tmp_sockaddr.sin_port= htons(uint16_t((u64<<32u)>>32u));

        int ret = sendto(udp_fd, data + sizeof(u32_t), data_len - (sizeof(u32_t)), 0, (struct sockaddr *)&tmp_addr.inner, tmp_addr.get_len());

        if (ret < 0) {
            mylog(log_warn, "sento returned %d,%s,%02x,%s\n", ret, get_sock_error(), int(tmp_addr.get_type()), tmp_addr.get_str());
            // perror("ret<0");
        }
        client_rotate_account(conn_info, data_len);
    } else {
        mylog(log_warn, "unknown packet,this shouldnt happen.\n");
        return -1;
    }
    return 0;
}

// Shared handshake1 response parser (used by both active connection and preconnect).
// Assumes data has already been read via recv_raw0(). Returns 0 on success.
static int process_handshake1_response(conn_info_t &c, char *data, int data_len) {
    packet_info_t &s = c.raw_info.send_info;
    packet_info_t &r = c.raw_info.recv_info;
    if (raw_mode == mode_faketcp && (r.syn == 1 || r.ack != 1)) return -1;
    if (reserved_parse_bare(data, data_len, data, data_len) != 0) return -1;
    if (!r.new_src_ip.equal(s.new_dst_ip) || r.src_port != s.dst_port) return -1;
    if (data_len < int(3 * sizeof(my_id_t))) return -1;

    my_id_t oppsite_id, my_id;
    memcpy(&oppsite_id, &data[0], sizeof(oppsite_id));
    oppsite_id = ntohl(oppsite_id);
    memcpy(&my_id, &data[sizeof(my_id_t)], sizeof(my_id));
    my_id = ntohl(my_id);
    if (my_id != c.my_id) return -1;

    c.oppsite_id = oppsite_id;
    c.state.client_current_state = client_handshake2;
    c.last_state_time = get_current_time();
    c.last_hb_sent_time = 0;
    return 0;
}

int client_on_raw_recv(conn_info_t &conn_info)  // called when raw fd received a packet.
{
    // A mixed-family client has one PF_PACKET watcher per family. Ignore a
    // packet unless that family currently belongs to the active or pending
    // connection.
    if (conn_info.raw_family != (int)raw_ip_version
        && (!pre.active || pre.conn.raw_family != (int)raw_ip_version)) {
#ifdef UDP2RAW_LINUX
        if (pre_recv_raw_packet() == 0) discard_raw_packet();
#endif
        return 0;
    }

    // Pre-connect classification: if a handshake response for the pending
    // connection arrived, route it to the preconnect state machine.
    if (pre.active && pre.conn.raw_family == (int)raw_ip_version
        && conn_info.state.client_current_state == client_ready) {
        // Peek at the raw packet to extract the server's TCP/UDP source port.
        // recvfrom(MSG_PEEK) on a PF_PACKET socket returns sockaddr_ll
        // (no port), so we parse the IP+UDP headers manually.
        char peek_buf[60];  // enough for IPv4/IPv6 header + UDP header
        int peek_len = recvfrom(raw_recv_fd, peek_buf, (int)sizeof(peek_buf),
                                 MSG_PEEK, nullptr, nullptr);
        if (peek_len >= 40) {  // min = IPv4(20) + UDP(8) or IPv6(40) + UDP(8)
            int transport_off = 0;
            int version = (unsigned char)peek_buf[0] >> 4;
            if (version == 4) {
                int ihl = ((unsigned char)peek_buf[0] & 0x0F) * 4;
                int protocol = (unsigned char)peek_buf[9];
                if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
                    transport_off = ihl;
            } else if (version == 6) {
                // IPv6: walk extension headers to find the TCP/UDP header
                int off = 40;
                int next_hdr = (unsigned char)peek_buf[6];  // IPv6 Next Header field
                while (off + 2 <= peek_len && next_hdr != IPPROTO_TCP && next_hdr != IPPROTO_UDP) {
                    if (next_hdr == 0 || next_hdr == 43 || next_hdr == 44 ||
                        next_hdr == 60 || next_hdr == 135) {
                        // Extension header: byte 0=next, byte 1=len in 8B units
                        if (off + 2 > peek_len) break;
                        next_hdr = (unsigned char)peek_buf[off];
                        int ext_len = ((unsigned char)peek_buf[off + 1] + 1) * 8;
                        off += ext_len;
                    } else if (next_hdr == 51 || next_hdr == 50) {
                        // AH / ESP — can't see through, bail
                        break;
                    } else {
                        break;  // unknown/unexpected next header
                    }
                }
                if (next_hdr == IPPROTO_TCP || next_hdr == IPPROTO_UDP) transport_off = off;
            }
            if (transport_off > 0 && peek_len >= transport_off + 4) {
                int src_port = ((unsigned char)peek_buf[transport_off] << 8)
                             | (unsigned char)peek_buf[transport_off + 1];
                // Demux on the full (src ip, src port) tuple, not the port
                // alone: if the standby shares the active flow's server port,
                // port-only classification feeds every active packet to the
                // standby and blackholes the tunnel for ~10s.
                int ip_match = 0;
                if (version == 4 && pre.endpoint.get_type() == AF_INET) {
                    ip_match = memcmp(peek_buf + 12, &pre.endpoint.inner.ipv4.sin_addr, 4) == 0;
                } else if (version == 6 && pre.endpoint.get_type() == AF_INET6) {
                    ip_match = memcmp(peek_buf + 8, &pre.endpoint.inner.ipv6.sin6_addr, 16) == 0;
                }
                if (ip_match && src_port == pre.new_dst_port) {
                    // This packet is for the preconnect — process it with
                    // pre.conn. Populate udp2raw's packet buffer once; each
                    // state-specific parser then consumes that same packet.
                    conn_info_t &pc = pre.conn;
#ifdef UDP2RAW_LINUX
                    if (pre_recv_raw_packet() < 0) return -1;
#endif
                    if (pc.state.client_current_state == client_tcp_handshake) {
                        char *data;
                        int data_len;
                        if (recv_raw0(pc.raw_info, data, data_len) < 0) return -1;
                        if (data_len != 0 || pc.raw_info.recv_info.syn != 1
                            || pc.raw_info.recv_info.ack != 1)
                            return -1;
                        if (pc.raw_info.recv_info.ack_seq != pc.raw_info.send_info.seq + 1) {
                            mylog(log_debug, "preconnect syn/ack sequence mismatch\n");
                            return -1;
                        }
                        pc.state.client_current_state = client_handshake1;
                        pc.last_state_time = get_current_time();
                        pc.last_hb_sent_time = 0;
                        pre_send_handshake1(pc);
                        return 0;
                    } else if (pc.state.client_current_state == client_handshake1) {
                        char *data;
                        int data_len;
                        if (recv_raw0(pc.raw_info, data, data_len) < 0) return -1;
                        if (data_len >= max_data_len + 1) return -1;
                        if (process_handshake1_response(pc, data, data_len) < 0) return -1;
                        // Send handshake2 through the shared raw socket; the
                        // preconnect is distinguished by its packet state.
                        pre_send_handshake2(pc);
                        return 0;
                    } else if (pc.state.client_current_state == client_handshake2) {
                        vector<char> type_vec;
                        vector<string> data_vec;
                        if (recv_safer_multi(pc, type_vec, data_vec) < 0) return -1;
                        if (!data_vec.empty()) {
                            pc.state.client_current_state = client_ready;
                            pc.last_hb_sent_time = 0;
                            pc.last_hb_recv_time = get_current_time();
                            pc.last_oppsite_roller_time = pc.last_hb_recv_time;
                            pre.ready_time = pc.last_hb_recv_time;
                            pre.heartbeat_confirmed = 0;
                            if (hb_mode == 0)
                                send_safer(pc, 'h', hb_buf, 0);
                            else
                                send_safer(pc, 'h', hb_buf, hb_len);
                            pc.last_hb_sent_time = get_current_time();
                            mylog(log_info, "preconnect handshake ready; awaiting heartbeat qualification\n");
                        }
                        return 0;
                    } else if (pc.state.client_current_state == client_ready) {
                        // Preconnect is idle — process heartbeats to keep alive
                        vector<char> type_vec;
                        vector<string> data_vec;
                        if (recv_safer_multi(pc, type_vec, data_vec) < 0) return -1;
                        for (int i = 0; i < (int)type_vec.size(); i++) {
                            if (type_vec[i] == 'h') {
                                pc.last_hb_recv_time = get_current_time();
                                pre.heartbeat_confirmed = 1;
                                mark_family_success(pc.raw_family);
                            }
                        }
                        if (pre.heartbeat_confirmed && pre.swap_requested)
                            swap_preconnect(conn_info);
                        return 0;
                    }
                    // If we get here, discard the packet (not an expected state)
                    discard_raw_packet();
                    return 0;
                }
            }
        }
    }

    if (conn_info.raw_family != (int)raw_ip_version) {
#ifdef UDP2RAW_LINUX
        if (pre_recv_raw_packet() == 0) discard_raw_packet();
#endif
        return 0;
    }

    char *data;
    int data_len;
    packet_info_t &send_info = conn_info.raw_info.send_info;
    packet_info_t &recv_info = conn_info.raw_info.recv_info;

    raw_info_t &raw_info = conn_info.raw_info;

    mylog(log_trace, "<client_on_raw_recv,send_info.ts_ack= %u>\n", send_info.ts_ack);

#ifdef UDP2RAW_LINUX
    if (pre_recv_raw_packet() < 0) return -1;
#endif

    if (conn_info.state.client_current_state == client_idle) {
        discard_raw_packet();
        // recv(raw_recv_fd, 0,0, 0  );
    } else if (conn_info.state.client_current_state == client_tcp_handshake || conn_info.state.client_current_state == client_tcp_handshake_dummy)  // received syn ack
    {
        assert(raw_mode == mode_faketcp);
        if (recv_raw0(raw_info, data, data_len) < 0) {
            return -1;
        }
        if (data_len >= max_data_len + 1) {
            mylog(log_debug, "data_len=%d >= max_data_len+1,ignored", data_len);
            return -1;
        }
        if (!recv_info.new_src_ip.equal(send_info.new_dst_ip) || recv_info.src_port != send_info.dst_port) {
            mylog(log_debug, "unexpected adress %s %s %d %d\n", recv_info.new_src_ip.get_str1(), send_info.new_dst_ip.get_str2(), recv_info.src_port, send_info.dst_port);
            return -1;
        }
        if (data_len == 0 && raw_info.recv_info.syn == 1 && raw_info.recv_info.ack == 1) {
            if (conn_info.state.client_current_state == client_tcp_handshake) {
                if (recv_info.ack_seq != send_info.seq + 1) {
                    mylog(log_debug, "seq ack_seq mis match\n");
                    return -1;
                }
                mylog(log_info, "state changed from client_tcp_handshake to client_handshake1\n");
            } else {
                send_info.seq = recv_info.ack_seq - 1;
                mylog(log_info, "state changed from client_tcp_dummy to client_handshake1\n");
                // send_info.ack_seq=recv_info.seq+1;
            }
            conn_info.state.client_current_state = client_handshake1;

            conn_info.last_state_time = get_current_time();
            conn_info.last_hb_sent_time = 0;
            client_on_timer(conn_info);
            return 0;
        } else {
            mylog(log_debug, "unexpected packet type,expected:syn ack\n");
            return -1;
        }
    } else if (conn_info.state.client_current_state == client_handshake1)  // recevied respond of handshake1
    {
        if (recv_bare(raw_info, data, data_len) != 0) {
            mylog(log_debug, "recv_bare failed!\n");
            return -1;
        }
        if (!recv_info.new_src_ip.equal(send_info.new_dst_ip) || recv_info.src_port != send_info.dst_port) {
            mylog(log_debug, "unexpected adress %s %s %d %d\n", recv_info.new_src_ip.get_str1(), send_info.new_dst_ip.get_str2(), recv_info.src_port, send_info.dst_port);
            return -1;
        }
        if (data_len < int(3 * sizeof(my_id_t))) {
            mylog(log_debug, "too short to be a handshake\n");
            return -1;
        }
        my_id_t tmp_oppsite_id;
        memcpy(&tmp_oppsite_id, &data[0], sizeof(tmp_oppsite_id));
        tmp_oppsite_id = ntohl(tmp_oppsite_id);

        my_id_t tmp_my_id;
        memcpy(&tmp_my_id, &data[sizeof(my_id_t)], sizeof(tmp_my_id));
        tmp_my_id = ntohl(tmp_my_id);

        my_id_t tmp_oppsite_const_id;
        memcpy(&tmp_oppsite_const_id, &data[sizeof(my_id_t) * 2], sizeof(tmp_oppsite_const_id));
        tmp_oppsite_const_id = ntohl(tmp_oppsite_const_id);

        if (tmp_my_id != conn_info.my_id) {
            mylog(log_debug, "tmp_my_id doesnt match\n");
            return -1;
        }

        if (raw_mode == mode_faketcp) {
            if (recv_info.ack_seq != send_info.seq) {
                mylog(log_debug, "seq ack_seq mis match\n");
                return -1;
            }
            if (recv_info.seq != send_info.ack_seq) {
                mylog(log_debug, "seq ack_seq mis match\n");
                return -1;
            }
        }
        conn_info.oppsite_id = tmp_oppsite_id;

        mylog(log_info, "changed state from to client_handshake1 to client_handshake2,my_id is %x,oppsite id is %x\n", conn_info.my_id, conn_info.oppsite_id);

        conn_info.state.client_current_state = client_handshake2;
        conn_info.last_state_time = get_current_time();
        conn_info.last_hb_sent_time = 0;
        client_on_timer(conn_info);

        return 0;
    } else if (conn_info.state.client_current_state == client_handshake2 || conn_info.state.client_current_state == client_ready)  // received heartbeat or data
    {
        vector<char> type_vec;
        vector<string> data_vec;
        recv_safer_multi(conn_info, type_vec, data_vec);
        if (data_vec.empty()) {
            mylog(log_debug, "recv_safer failed!\n");
            return -1;
        }

        for (int i = 0; i < (int)type_vec.size(); i++) {
            char type = type_vec[i];
            char *data = (char *)data_vec[i].c_str();  // be careful, do not append data to it
            int data_len = data_vec[i].length();
            client_on_raw_recv_hs2_or_ready(conn_info, type, data, data_len);
        }

        return 0;
    } else {
        mylog(log_fatal, "unknown state,this shouldnt happen.\n");
        myexit(-1);
    }

    return 0;
}
int client_on_udp_recv(conn_info_t &conn_info) {
    int recv_len;
    char buf[buf_len];
    address_t::storage_t udp_new_addr_in = {{0}};
    socklen_t udp_new_addr_len = sizeof(address_t::storage_t);
    if ((recv_len = recvfrom(udp_fd, buf, max_data_len + 1, 0,
                             (struct sockaddr *)&udp_new_addr_in, &udp_new_addr_len)) == -1) {
        mylog(log_debug, "recv_from error,%s\n", get_sock_error());
        return -1;
        // myexit(1);
    };

    if (recv_len == max_data_len + 1) {
        mylog(log_warn, "huge packet, data_len > %d,dropped\n", max_data_len);
        return -1;
    }

    if (recv_len >= mtu_warn) {
        mylog(log_warn, "huge packet,data len=%d (>=%d).strongly suggested to set a smaller mtu at upper level,to get rid of this warn\n ", recv_len, mtu_warn);
    }

    address_t tmp_addr;
    tmp_addr.from_sockaddr((sockaddr *)&udp_new_addr_in, udp_new_addr_len);
    u32_t conv;

    if (!conn_info.blob->conv_manager.c.is_data_used(tmp_addr)) {
        if (conn_info.blob->conv_manager.c.get_size() >= max_conv_num) {
            mylog(log_warn, "ignored new udp connect bc max_conv_num exceed\n");
            return -1;
        }
        conv = conn_info.blob->conv_manager.c.get_new_conv();
        conn_info.blob->conv_manager.c.insert_conv(conv, tmp_addr);
        mylog(log_info, "new packet from %s,conv_id=%x\n", tmp_addr.get_str(), conv);
    } else {
        conv = conn_info.blob->conv_manager.c.find_conv_by_data(tmp_addr);
    }

    conn_info.blob->conv_manager.c.update_active_time(conv);

    if (conn_info.state.client_current_state == client_ready) {
        send_data_safer(conn_info, buf, recv_len, conv);
        client_rotate_account(conn_info, recv_len);
        stall_win_bytes += (u64_t)recv_len;
    }
    return 0;
}
void udp_accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    conn_info_t &conn_info = *((conn_info_t *)watcher->data);
    select_client_family(conn_info.raw_family);
    client_on_udp_recv(conn_info);
}
struct client_raw_watcher_ctx_t {
    conn_info_t *conn;
    int sock_index;
};
void raw_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    if (is_udp2raw_mp) assert(0 == 1);
    client_raw_watcher_ctx_t *ctx = (client_raw_watcher_ctx_t *)watcher->data;
    if (ctx->sock_index >= 0)
        use_listen_sock_by_index(ctx->sock_index);
    conn_info_t &conn_info = *ctx->conn;
    client_on_raw_recv(conn_info);
}
#ifdef UDP2RAW_MP
void async_cb(struct ev_loop *loop, struct ev_async *watcher, int revents) {
    conn_info_t &conn_info = *((conn_info_t *)watcher->data);

    if (send_with_pcap && !pcap_header_captured) {
        int empty = 0;
        char *p;
        int len;
        pthread_mutex_lock(&queue_mutex);
        empty = my_queue.empty();
        if (!empty) {
            my_queue.peek_front(p, len);
            my_queue.pop_front();
        }
        pthread_mutex_unlock(&queue_mutex);
        if (empty) return;

        pcap_header_captured = 1;
        assert(pcap_link_header_len != -1);
        memcpy(pcap_header_buf, p, max_data_len);

        log_bare(log_info, "link level header captured:\n");
        unsigned char *tmp = (unsigned char *)pcap_header_buf;
        pcap_captured_full_len = len;
        for (int i = 0; i < pcap_link_header_len; i++)
            log_bare(log_info, "<%x>", (u32_t)tmp[i]);

        log_bare(log_info, "\n");
        return;
    }

    // mylog(log_info,"async_cb called\n");
    while (1) {
        int empty = 0;
        char *p;
        int len;
        pthread_mutex_lock(&queue_mutex);
        empty = my_queue.empty();
        if (!empty) {
            my_queue.peek_front(p, len);
            my_queue.pop_front();
        }
        pthread_mutex_unlock(&queue_mutex);

        if (empty) break;
        if (g_fix_gro == 0 && len > max_data_len) {
            mylog(log_warn, "huge packet %d > %d, dropped. maybe you need to turn down mtu at upper level, or maybe you need the --fix-gro option\n", len, max_data_len);
            break;
        }

        int new_len = len - pcap_link_header_len;
        memcpy(g_packet_buf, p + pcap_link_header_len, new_len);
        g_packet_buf_len = new_len;
        assert(g_packet_buf_cnt == 0);
        g_packet_buf_cnt++;
        client_on_raw_recv(conn_info);
    }
}
#endif
void clear_timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents) {
    conn_info_t &conn_info = *((conn_info_t *)watcher->data);
    client_on_timer(conn_info);
}
void fifo_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    conn_info_t &conn_info = *((conn_info_t *)watcher->data);

    char buf[buf_len];
    int fifo_fd = watcher->fd;

    int len = read(fifo_fd, buf, sizeof(buf));
    if (len < 0) {
        mylog(log_warn, "fifo read failed len=%d,errno=%s\n", len, get_sock_error());
        return;
    }
    buf[len] = 0;
    while (len >= 1 && buf[len - 1] == '\n')
        buf[len - 1] = 0;
    mylog(log_info, "got data from fifo,len=%d,s=[%s]\n", len, buf);
    if (strcmp(buf, "reconnect") == 0) {
        mylog(log_info, "received command: reconnect\n");
        conn_info.state.client_current_state = client_idle;
        conn_info.my_id = get_true_random_number_nz();
        // A forced reconnect makes the standby's handshake stale — drop it.
        if (pre.active) pre.reset();
    } else if (strcmp(buf, "rotate") == 0) {
        mylog(log_info, "received command: rotate\n");
        client_rotate_port(conn_info, "fifo command");
    } else {
        mylog(log_info, "unknown command\n");
    }
}
int client_event_loop() {
    char buf[buf_len];

    conn_info_t conn_info;
    conn_info.my_id = get_true_random_number_nz();
    conn_info.local_const_id = const_id;
    conn_info.raw_family = remote_addr.get_type();

    conn_info.prepare();
    packet_info_t &send_info = conn_info.raw_info.send_info;
    packet_info_t &recv_info = conn_info.raw_info.recv_info;

#ifdef UDP2RAW_LINUX
    if (lower_level) {
        if (lower_level_manual) {
            int index;
            init_ifindex(if_name, raw_send_fd, index);
            // init_ifindex(if_name);
            memset(&send_info.addr_ll, 0, sizeof(send_info.addr_ll));
            send_info.addr_ll.sll_family = AF_PACKET;
            send_info.addr_ll.sll_ifindex = index;
            send_info.addr_ll.sll_halen = ETHER_ADDR_LEN;
            send_info.addr_ll.sll_protocol = htons(ETH_P_IP);
            memcpy(&send_info.addr_ll.sll_addr, dest_hw_addr, ETHER_ADDR_LEN);
            mylog(log_info, "we are running at lower-level (manual) mode\n");
        } else {
            u32_t dest_ip;
            string if_name_string;
            string hw_string;
            assert(remote_addr.get_type() == AF_INET);

            if (retry_on_error == 0) {
                if (find_lower_level_info(remote_addr.inner.ipv4.sin_addr.s_addr, dest_ip, if_name_string, hw_string) != 0) {
                    mylog(log_fatal, "auto detect lower-level info failed for %s,specific it manually\n", remote_addr.get_ip());
                    myexit(-1);
                }
            } else {
                int ok = 0;
                while (!ok) {
                    if (find_lower_level_info(remote_addr.inner.ipv4.sin_addr.s_addr, dest_ip, if_name_string, hw_string) != 0) {
                        mylog(log_warn, "auto detect lower-level info failed for %s,retry in %d seconds\n", remote_addr.get_ip(), retry_on_error_interval);
                        sleep(retry_on_error_interval);
                    } else {
                        ok = 1;
                    }
                }
            }
            mylog(log_info, "we are running at lower-level (auto) mode,%s %s %s\n", my_ntoa(dest_ip), if_name_string.c_str(), hw_string.c_str());

            u32_t hw[6];
            memset(hw, 0, sizeof(hw));
            sscanf(hw_string.c_str(), "%x:%x:%x:%x:%x:%x", &hw[0], &hw[1], &hw[2],
                   &hw[3], &hw[4], &hw[5]);

            mylog(log_warn,
                  "make sure this is correct:   if_name=<%s>  dest_mac_adress=<%02x:%02x:%02x:%02x:%02x:%02x>  \n",
                  if_name_string.c_str(), hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
            for (int i = 0; i < 6; i++) {
                dest_hw_addr[i] = uint8_t(hw[i]);
            }

            // mylog(log_fatal,"--lower-level auto for client hasnt been implemented\n");
            int index;
            init_ifindex(if_name_string.c_str(), raw_send_fd, index);

            memset(&send_info.addr_ll, 0, sizeof(send_info.addr_ll));
            send_info.addr_ll.sll_family = AF_PACKET;
            send_info.addr_ll.sll_ifindex = index;
            send_info.addr_ll.sll_halen = ETHER_ADDR_LEN;
            send_info.addr_ll.sll_protocol = htons(ETH_P_IP);
            memcpy(&send_info.addr_ll.sll_addr, dest_hw_addr, ETHER_ADDR_LEN);
            // mylog(log_info,"we are running at lower-level (manual) mode\n");
        }
    }
#endif

#ifdef UDP2RAW_MP

    address_t tmp_addr;
    if (get_src_adress2(tmp_addr, remote_addr) != 0) {
        mylog(log_error, "get_src_adress() failed\n");
        myexit(-1);
    }
    if (strcmp(dev, "") == 0) {
        mylog(log_info, "--dev have not been set, trying to detect automatically, available devices:\n");

        mylog(log_info, "available device(device name: ip address ; description):\n");

        char errbuf[PCAP_ERRBUF_SIZE];

        int found = 0;

        pcap_if_t *interfaces, *d;
        if (pcap_findalldevs(&interfaces, errbuf) == -1) {
            mylog(log_fatal, "error in pcap_findalldevs(),%s\n", errbuf);
            myexit(-1);
        }

        for (pcap_if_t *d = interfaces; d != NULL; d = d->next) {
            log_bare(log_warn, "%s:", d->name);
            int cnt = 0;
            for (pcap_addr_t *a = d->addresses; a != NULL; a = a->next) {
                if (a->addr == NULL) {
                    log_bare(log_debug, " [a->addr==NULL]");
                    continue;
                }
                if (a->addr->sa_family == AF_INET || a->addr->sa_family == AF_INET6) {
                    cnt++;

                    if (a->addr->sa_family == AF_INET) {
                        char s[max_addr_len];
                        inet_ntop(AF_INET, &((struct sockaddr_in *)a->addr)->sin_addr, s, max_addr_len);
                        log_bare(log_warn, " [%s]", s);

                        if (a->addr->sa_family == raw_ip_version) {
                            if (((struct sockaddr_in *)a->addr)->sin_addr.s_addr == tmp_addr.inner.ipv4.sin_addr.s_addr) {
                                found++;
                                strcpy(dev, d->name);
                            }
                        }
                    } else {
                        assert(a->addr->sa_family == AF_INET6);

                        char s[max_addr_len];
                        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)a->addr)->sin6_addr, s, max_addr_len);
                        log_bare(log_warn, " [%s]", s);

                        if (a->addr->sa_family == raw_ip_version) {
                            if (memcmp(&((struct sockaddr_in6 *)a->addr)->sin6_addr, &tmp_addr.inner.ipv6.sin6_addr, sizeof(struct in6_addr)) == 0) {
                                found++;
                                strcpy(dev, d->name);
                            }
                        }
                    }
                } else {
                    log_bare(log_debug, " [unknow:%d]", int(a->addr->sa_family));
                }
            }
            if (cnt == 0) log_bare(log_warn, " [no ip found]");
            if (d->description == 0) {
                log_bare(log_warn, "; (no description available)");
            } else {
                log_bare(log_warn, "; %s", d->description);
            }
            log_bare(log_warn, "\n");
        }

        if (found == 0) {
            mylog(log_fatal, "no matched device found for ip: [%s]\n", tmp_addr.get_ip());
            myexit(-1);
        } else if (found == 1) {
            mylog(log_info, "using device:[%s], ip: [%s]\n", dev, tmp_addr.get_ip());
        } else {
            mylog(log_fatal, "more than one devices found for ip: [%s] , you need to use --dev manually\n", tmp_addr.get_ip());
            myexit(-1);
        }
    } else {
        mylog(log_info, "--dev has been manually set, using device:[%s]\n", dev);
    }
#endif

    send_info.src_port = 0;
    memset(&send_info.new_src_ip, 0, sizeof(send_info.new_src_ip));

    int i, j, k;
    int ret;

    send_info.new_dst_ip.from_address_t(remote_addr);
    send_info.dst_port = remote_addr.get_port();

    if (rotate_bytes > 0) {
        rotate_next_threshold = rotate_pick_threshold();
        rotate_last_time = get_current_time();
        mylog(log_info, "client port rotation enabled: threshold=%llu bytes (base %llu, jitter ±%d%%), min_interval=%ds, max_interval=%ds, port range=%d:%d\n",
              rotate_next_threshold, (unsigned long long)rotate_bytes, rotate_jitter, rotate_min_interval, rotate_max_interval, rotate_port_min, rotate_port_max);
    }
#ifdef UDP2RAW_LINUX
    if (remote_addr.get_type() == AF_INET6
        && rotate_v6_prefix[0] != 0 && rotate_v6_dev[0] != 0) {
        client_rotate_v6_source();  // pick the first source address before the initial connect
    }
#endif

    udp_fd = socket(local_addr.get_type(), SOCK_DGRAM, IPPROTO_UDP);
    set_buf_size(udp_fd, socket_buf_size);

    if (::bind(udp_fd, (struct sockaddr *)&local_addr.inner, local_addr.get_len()) == -1) {
        mylog(log_fatal, "socket bind error\n");
        // perror("socket bind error");
        myexit(1);
    }
    setnonblocking(udp_fd);

    // epollfd = epoll_create1(0);

    // const int max_events = 4096;
    // struct epoll_event ev, events[max_events];
    // if (epollfd < 0) {
    //	mylog(log_fatal,"epoll return %d\n", epollfd);
    //	myexit(-1);
    // }

    struct ev_loop *loop = ev_default_loop(0);
    assert(loop != NULL);

    // ev.events = EPOLLIN;
    // ev.data.u64 = udp_fd;
    // ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, udp_fd, &ev);
    // if (ret!=0) {
    //	mylog(log_fatal,"add  udp_listen_fd error\n");
    //	myexit(-1);
    // }

    struct ev_io udp_accept_watcher;

    udp_accept_watcher.data = &conn_info;
    ev_io_init(&udp_accept_watcher, udp_accept_cb, udp_fd, EV_READ);
    ev_io_start(loop, &udp_accept_watcher);

    // ev.events = EPOLLIN;
    // ev.data.u64 = raw_recv_fd;

    // ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_recv_fd, &ev);
    // if (ret!= 0) {
    //	mylog(log_fatal,"add raw_fd error\n");
    //	myexit(-1);
    // }

#ifdef UDP2RAW_LINUX
    struct ev_io raw_recv_watchers[MAX_LISTEN_SOCKS];
    client_raw_watcher_ctx_t raw_watcher_ctx[MAX_LISTEN_SOCKS];
    int raw_watcher_cnt = 0;
    if (rotate_endpoint_spec_cnt > 0) {
        for (int idx = 0; idx < listen_sock_cnt; idx++) {
            raw_watcher_ctx[raw_watcher_cnt].conn = &conn_info;
            raw_watcher_ctx[raw_watcher_cnt].sock_index = idx;
            raw_recv_watchers[raw_watcher_cnt].data = &raw_watcher_ctx[raw_watcher_cnt];
            ev_io_init(&raw_recv_watchers[raw_watcher_cnt], raw_recv_cb,
                       listen_socks[idx].recv_fd, EV_READ);
            ev_io_start(loop, &raw_recv_watchers[raw_watcher_cnt]);
            raw_watcher_cnt++;
        }
        select_client_family(conn_info.raw_family);
    } else {
        raw_watcher_ctx[0].conn = &conn_info;
        raw_watcher_ctx[0].sock_index = -1;
        raw_recv_watchers[0].data = &raw_watcher_ctx[0];
        ev_io_init(&raw_recv_watchers[0], raw_recv_cb, raw_recv_fd, EV_READ);
        ev_io_start(loop, &raw_recv_watchers[0]);
        raw_watcher_cnt = 1;
    }
#endif

#ifdef UDP2RAW_MP
    g_default_loop = loop;
    async_watcher.data = &conn_info;
    ev_async_init(&async_watcher, async_cb);
    ev_async_start(loop, &async_watcher);

    init_raw_socket();  // must be put after dev detection
#endif

    // set_timer(epollfd,timer_fd);
    struct ev_timer clear_timer;

    clear_timer.data = &conn_info;
    ev_timer_init(&clear_timer, clear_timer_cb, 0, timer_interval / 1000.0);
    ev_timer_start(loop, &clear_timer);

    mylog(log_debug, "send_raw : from %s %d  to %s %d\n", send_info.new_src_ip.get_str1(), send_info.src_port, send_info.new_dst_ip.get_str2(), send_info.dst_port);

    int fifo_fd = -1;

    struct ev_io fifo_watcher;
    fifo_watcher.data = &conn_info;

    if (fifo_file[0] != 0) {
        fifo_fd = create_fifo(fifo_file);

        ev_io_init(&fifo_watcher, fifo_cb, fifo_fd, EV_READ);
        ev_io_start(loop, &fifo_watcher);

        mylog(log_info, "fifo_file=%s\n", fifo_file);
    }

    ev_run(loop, 0);
    return 0;
}
