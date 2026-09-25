# Reliability / SRE rules.

# Tail latency SLO breach per service, evaluated continuously over a sliding
# 30 second window with 1 second panes.
rule latency_slo_breach {
  severity high
  description "p99 latency above 750ms over 30s with meaningful traffic"
  tags ["slo", "latency"]
  aggregate over 30s step 1s
  from http.request
  having count() >= 20 and p99(latency_ms) > 750
  emit {
    p50_ms = p50(latency_ms)
    p99_ms = p99(latency_ms)
    max_ms = max(latency_ms)
    rps = rate()
  }
}

# Error-rate burn per service and path.
rule error_burst {
  severity medium
  description "5xx ratio above 20% over 1m for a path with >= 50 requests"
  aggregate over 1m step 5s
  from http.request
  by path
  having count() >= 50 and sum(if(status >= 500, 1, 0)) / count() > 0.2
  emit {
    requests = count()
    errors = sum(if(status >= 500, 1, 0))
    path = group
  }
}

# Absence detection: a service started but never reported a heartbeat.
rule missing_heartbeat {
  severity high
  description "Service started but sent no heartbeat within 30s"
  tags ["liveness"]
  within 30s
  sequence {
    start: service.start
    !hb: service.heartbeat
  }
  emit {
    version = start.version
  }
}

# Crash loop: 3+ restarts within 5 minutes.
rule crash_loop {
  severity high
  description "Service restarted 3+ times within 5 minutes"
  within 5m
  suppress 5m
  sequence {
    restart: service.start[3:]
  }
  emit {
    restarts = count(restart)
    last_version = restart.version
  }
}
