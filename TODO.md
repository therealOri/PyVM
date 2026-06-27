# VM detection todos

vm_core:
- Make faster.
- Add more quirks.
- Tweak settings, paths, timings, etc.
- Make timing tests more consistent?


Enhancement Opportunities
- [ ] Parallelize independent gatherers with ThreadPoolExecutor
- [ ] Nested virtualization detection (inner + outer hypervisor markers)
- [ ] Tiered confidence weighting (hard evidence vs soft heuristics)
- [ ] Intel/Xeon thread specification validation database
- [ ] GPU driver fingerprinting (qxl/virtio-detectable drivers)

<br>

vm_cli | Polish / UX:
- [ ] Configurable sensitivity thresholds (aggressive/steady/evasive modes)
- [ ] JSON/XML output formats for automated pipelines
- [ ] Unit tests for each gatherer function
- [ ] Benchmark suite comparing detection speed vs accuracy trade-offs
- [ ] False positive documentation and test coverage
- [ ] Add loading animation while it scans.
- TBD
__ __


resources:
- https://github.com/ayoubfaouzi/al-khaser
- https://github.com/d4rksystem/VBoxCloak
- https://github.com/bRootForceOfficial/vbox_stealth
- https://www.youtube.com/watch?v=-On6bWFXuM8
    
