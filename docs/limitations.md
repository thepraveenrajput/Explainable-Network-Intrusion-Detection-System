# Limitations, Operational Context, and Ethical Considerations

## 1. Operational Limitations
- **Offline Flow Analysis vs. Live Packet Sniffing**:
  This framework analyzes pre-extracted tabular network flow records (e.g., NetFlow, IPFIX, CICFlowMeter statistics). It does **not** capture raw network packets in real-time from kernel interfaces (`AF_PACKET`, `libpcap`). Production deployment would require an upstream flow generator (such as Zeek or nProbe) feeding structured records into the system.
- **Latency of Complex Ensembles**:
  While our C++17 single-tree engine provides sub-millisecond inference, running heavy SHAP calculations locally for thousands of flows simultaneously is computationally intensive. In production, local explanations should be triggered on demand for high-risk triage rather than in real-time on every benign flow.

## 2. Machine Learning Limitations
- **Concept Drift & Zero-Day Attacks**:
  Network traffic and adversarial tactics continuously evolve. Models trained on historical datasets (such as CIC-IDS2017) may exhibit high false-negative rates when encountering novel zero-day attack patterns or obfuscated payloads. Periodic retraining and model drift monitoring are essential.
- **Adversarial Evasion**:
  Adversaries can manipulate flow characteristics without altering malicious payload functionality (e.g. introducing random packet inter-arrival delays or padding packet lengths) to evade tree-based decision boundaries.
- **Correlated Features in Explainability**:
  Many network flow features exhibit high multicollinearity (e.g. `Total Fwd Packets` and `Subflow Fwd Packets`). High correlation can cause feature importance and SHAP attribution values to split across redundant variables, making individual feature rankings sensitive to slight data variations. Explanations should be interpreted as predictive indicators rather than definitive causal proofs.

## 3. Ethical & Cybersecurity Disclosures
- **Defensive Purpose**:
  This software is developed strictly for educational, defensive, and academic research purposes to improve threat visibility and auditability in Security Operations Centers.
- **No Guarantee of Absolute Security**:
  No machine learning model is completely free of false negatives. Downstream systems must never use this framework as the sole line of perimeter defense without human-in-the-loop oversight and layered defense-in-depth security policies.
