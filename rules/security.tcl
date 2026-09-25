# Security correlation rules (Tempora Correlation Language).

# Credential stuffing / brute force: at least 5 failures followed by a success
# for the same source IP within 2 minutes, with no password reset in between.
rule brute_force_then_success {
  severity critical
  description "5+ authentication failures followed by a success from the same source"
  tags ["mitre:T1110", "auth"]
  within 2m
  suppress 10m
  max_runs 8
  sequence {
    fail: auth.failure[5:]
    !reset: auth.password_reset
    ok: auth.success where user == fail.user
  }
  emit {
    user = ok.user
    failures = count(fail)
    method = ok.method
    elapsed_ms = elapsed_ms()
  }
}

# Horizontal port scan: one source touching many distinct destination ports.
rule port_scan {
  severity high
  description "A single source contacted 25+ distinct destination ports within 10s"
  tags ["mitre:T1046", "network"]
  aggregate over 10s step 1s
  from net.flow
  where proto == "tcp" and not cidr(key, "10.0.0.0/8")
  having distinct(dst_port) >= 25
  emit {
    distinct_ports = distinct(dst_port)
    flows = count()
    bytes = sum(bytes)
  }
}

# Privilege escalation chain: new process spawned by a web server shortly
# after a request to an admin path, then an outbound connection.
rule webshell_chain {
  severity critical
  description "Admin-path request, shell spawned by web server, then outbound connection"
  tags ["mitre:T1505.003"]
  within 30s
  sequence {
    req: http.request where starts_with(path, "/admin") or contains(path, "..")
    proc: process.start where parent in ["nginx", "httpd", "php-fpm"] and name in ["sh", "bash", "dash"]
    conn: net.connect where not cidr(dst_ip, "10.0.0.0/8") and not cidr(dst_ip, "192.168.0.0/16")
  }
  emit {
    shell = proc.name
    parent = proc.parent
    dst = conn.dst_ip
    path = req.path
  }
}
