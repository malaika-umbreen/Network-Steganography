# 🔍 A Transformer-Based Detector for Network Steganography

<div align="center">

<img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/PyTorch-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white"/>
<img src="https://img.shields.io/badge/Jupyter-F37626?style=for-the-badge&logo=jupyter&logoColor=white"/>
<img src="https://img.shields.io/badge/Status-Completed-00C176?style=for-the-badge"/>
<img src="https://img.shields.io/badge/Paper-Under_Review-orange?style=for-the-badge"/>

**A Transformer-Based Detector for Network Steganography with Improved Generalization**



<img width="484" height="290" alt="image" src="https://github.com/user-attachments/assets/7a80ad5a-2085-4004-a27d-f79a2f13d53d" />




</div>

---

##  Overview

This project presents a deep learning–based approach to detect **network steganography** using a **Transformer architecture**. The system analyzes network traffic behavior and identifies covert communication hidden within standard protocols such as **ICMP, TCP, UDP, and DNS**.

The goal is to enhance cybersecurity by detecting hidden data exfiltration techniques that bypass traditional security mechanisms.


<img width="1297" height="730" alt="image" src="https://github.com/user-attachments/assets/c92e5efc-df6f-4461-94b8-4eab7f04cda3" />


---

##  Key Features

* 🔹 Detection of covert network traffic
* 🔹 Supports multiple protocols: **ICMP, TCP, UDP, DNS**
* 🔹 Transformer-based deep learning model
* 🔹 Flow-level feature extraction (225+ features)
* 🔹 Binary classification (Normal vs Covert)
* 🔹 Multi-class classification of steganography techniques:

  * Header Manipulation
  * Timing Obfuscation
  * Flow Blending

---

## Project Architecture

### 🔄 Workflow

<img width="1089" height="738" alt="image" src="https://github.com/user-attachments/assets/33e20248-3d51-4b75-a125-fd4509373ecb" />

1. **Data Generation (Lab Setup)**

   * Covert traffic generated using tools (e.g., ptunnel, dnscat2)
   * Normal traffic collected from regular applications

<img width="546" height="368" alt="image" src="https://github.com/user-attachments/assets/a0d734df-936d-48f2-a23c-63ca259064b2" />

2. **Data Collection**

   * Packet capture using Wireshark
   * Traffic aggregation into flow-based datasets

<img width="1091" height="718" alt="image" src="https://github.com/user-attachments/assets/d719e807-da53-4a2f-afa4-93d6833708a8" />

3. **Feature Categorization**

   * Three Covert Techniques Features
   * Header Manipulation, Flow Blending , Timing Obfuscation
   * 225 Input features total
   * Three labels (label_technique, label_protocol , label_binary)
     
<img width="1092" height="725" alt="image" src="https://github.com/user-attachments/assets/3a68f9f3-61c7-4faa-bbe2-f427da5ce9aa" />


4. **Preprocessing Pipeline**

   * Data Cleaning (remove duplicates, missing values)
   * Feature Scaling (StandardScaler)
   * Label Encoding
   * Train/Test Split (80/20)
   * Tensor Conversion (PyTorch/TensorFlow)

<img width="1088" height="715" alt="image" src="https://github.com/user-attachments/assets/532a012d-a84b-4ad9-9505-d82c281f12fb" />
     

5. **Model Development**

   * Transformer-based architecture
   * Multi-head attention mechanism
   * Behavioral learning from network flows

<img width="1320" height="1860" alt="image" src="https://github.com/user-attachments/assets/7b1cd56e-9aa8-45db-b3cd-c799f7de9d55" />


6. **Evaluation**

   * Accuracy, Precision, Recall, F1-score
   * Confusion Matrix

<img width="734" height="361" alt="image" src="https://github.com/user-attachments/assets/71a8f39d-27a9-42fe-b5eb-5544e840b318" />

---

## 🏗️ System Design

**Pipeline Flow:**

Attacker → Covert Traffic Generation → Network Channel (ICMP | TCP | UDP | DNS) → Organization Network → SOC Monitoring → Transformer-Based Detector → Output (Normal / Covert + Technique Classification)

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/92a7f334-8dbc-41f2-b12f-4e7cddc74ebe" />



---

## Dataset Details

* Total Features: **228**


<img width="572" height="148" alt="image" src="https://github.com/user-attachments/assets/d5e407de-5e27-4adc-ab16-fe8d0a114c32" />


  * Input Features: **225**
  * Label Columns: **3**
* Protocols Included:

  * ICMP
  * TCP
  * UDP
  * DNS

<img width="544" height="364" alt="image" src="https://github.com/user-attachments/assets/c053c809-0d3b-4fc7-906b-7ad49765b8f2" />

---
📁 Repository Structure
```
Network-Steganography/
│
├── 3_levels_Protocol_wise_Dataset/     # Labeled network traffic datasets
│   ├── DNS/
│   │   ├── dns_covert_labeled.csv
│   │   └── dns_normal_labeled.csv
│   ├── ICMP/
│   │   ├── icmp_covert_labeled.csv
│   │   └── icmp_normal_labeled.csv
│   ├── TCP/
│   │   ├── tcp_stego_labeled.csv
│   │   └── tcp_normal_labeled.csv
│   └── UDP/
│       ├── udp_covert_labeled.csv
│       └── udp_normal_labeled.csv
│
├── Covert_Scripts/                     # Scripts used to generate covert traffic
│   ├── ICMP_Covert_script.py
│   ├── TCP_Covert_script.py
│   └── UDP__Covert_script.py
│
├── Flow_Features_Technique_Wise/       # Feature descriptions per protocol
│   ├── DNS Flow Features.txt
│   ├── ICMP Flow features.txt
│   ├── TCP Flow features.txt
│   └── UDP Flow features.txt
│
├── Images/
|   ├── Full Architecture_.jpg                                      # Architecture diagrams & result charts
│   ├── System-Design.png
│   ├── Feature Categorization_.jpg
│   ├── Datasetgeneration.png
│   ├── Preprocessing.png
│   ├── loto_accuracy_chart.png
│   └── loto_confusion_matrices.png
|
|
├── Web Application_Screenshots/       # All Web App  realated Screenshots
│   ├── App Architecture Design Diagram.png
|   ├── Register .png
|   ├── Login .png
|   ├── Dashboard .png
|   ├── Flow Details .png
|   ├── Technique Analysis .png
|   ├── Protocol Analysis .png
|   ├── Detection logs .png
│
|
├── Literature_Review/                  # Related work & references
│
├── Model_Training_Documentation/       # Training & preprocessing documentation
│   ├── Dataset_Generation_Complete_.pdf
│   ├── FINAL_Preprocessing_Thesis_C...
│   ├── Multi_Protocol_Preprocessing_.pdf
│   ├── Dataset_Combining_Details.pdf
│   └── Thesis_Testing_Chapter.docx
│
├── Protocol_Wise_Dataset_Info/         # Feature documentation per protocol
│   ├── DNS- Features Description.docx
│   ├── ICMP_Features_Summary_Table.xlsx
│   ├── Normal vs DNS Covert Features.docx
│   └── ICMP-TCP-UDP Table-Wise Techniques.docx
│
├── Tools_Wise_Dataset_Comparison/      # Tool-by-tool dataset analysis
│   ├── DNS-&-IPV6-tools.docx
│   └── UDP-ICMP-tools-from-dataset.docx
│
├── LICENSE
└── README.md
```
---
🛠️ Tech Stack
![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-EE4C2C?style=flat-square&logo=pytorch&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-009688?style=flat-square)
![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=flat-square&logo=wireshark&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-150458?style=flat-square&logo=pandas&logoColor=white)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)
![Jupyter](https://img.shields.io/badge/Jupyter-F37626?style=flat-square&logo=jupyter&logoColor=white)
---

## 📈 Results

* Achieved high accuracy in detecting covert traffic
* Successfully classified different steganography techniques
* Demonstrated effectiveness of Transformer models in cybersecurity

 <img width="1128" height="502" alt="image" src="https://github.com/user-attachments/assets/ed8fffe2-8fc7-40eb-9401-a9a9ef2debe5" />
 

---

## Applications

* Network Intrusion Detection Systems (NIDS)
* Security Operations Centers (SOC)
* Data Exfiltration Detection
* Enterprise Network Security

---

## Future Work

* Real-time deployment in SOC environments
* Integration with SIEM tools (e.g., Wazuh)
* Hybrid models (CNN + Transformer)
* Larger real-world datasets
* More Covert techniques used

---

##  Author

**Malaika Umbreen**
BS Information Technology – Final Year
Research Area: Cybersecurity & Artificial Intelligence

---

## 📜 License

This project is for Academic and Research purposes.

---
