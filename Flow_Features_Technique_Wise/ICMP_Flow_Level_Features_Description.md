# ICMP Covert Channel Detection - Required Flow-Level Features
## Network Steganography Multi-Class Classification (FYP)


## Feature Categories for Anti-Forensic Technique Detection

### **TECHNIQUE 1: TIME OBFUSCATION**

#### Flow-Level Temporal Features

**Basic Timing Statistics:**
1. `flow_duration` - Total duration of the flow (last_packet_time - first_packet_time)
2. `flow_packets_per_second` - Number of packets per second in the flow
3. `flow_bytes_per_second` - Number of bytes per second in the flow
4. `avg_inter_arrival_time` - Mean time between consecutive packets
5. `std_inter_arrival_time` - Standard deviation of inter-arrival times
6. `min_inter_arrival_time` - Minimum time gap between packets
7. `max_inter_arrival_time` - Maximum time gap between packets
8. `median_inter_arrival_time` - Median time gap between packets

**Advanced Timing Patterns:**
9. `inter_arrival_time_variance` - Variance of packet timing (jitter detection)
10. `inter_arrival_time_cv` - Coefficient of variation (std/mean) of timing
11. `timing_entropy` - Shannon entropy of inter-arrival time distribution
12. `timing_skewness` - Skewness of timing distribution
13. `timing_kurtosis` - Kurtosis of timing distribution (detect outliers)

**Burst Detection:**
14. `burst_count` - Number of packet bursts (packets within <100µs)
15. `burst_ratio` - Ratio of burst packets to total packets
16. `max_burst_size` - Maximum number of consecutive packets in a burst
17. `avg_burst_size` - Average number of packets per burst
18. `burst_duration` - Total time spent in burst mode

**Delay Analysis:**
19. `delay_spike_count` - Number of abnormal delays (>1 second)
20. `delay_spike_ratio` - Ratio of delay spikes to total intervals
21. `max_delay` - Maximum inter-packet delay
22. `delay_variance` - Variance of delays exceeding threshold

**Periodicity Detection:**
23. `timing_autocorrelation` - Autocorrelation of inter-arrival times
24. `timing_periodicity_score` - Measure of periodic timing patterns
25. `timing_regularity_index` - Regularity of packet timing

**Window-Based Features:**
26. `timing_variance_first_10` - Variance of first 10 packet timings
27. `timing_variance_last_10` - Variance of last 10 packet timings
28. `timing_variance_ratio` - Ratio of early to late timing variance
29. `rolling_avg_timing_std` - Standard deviation of rolling average timing

---

### **TECHNIQUE 2: HEADER MANIPULATION**

#### ICMP-Specific Header Features

**ICMP Identifier Field:**
30. `icmp_id_count` - Number of unique ICMP IDs in the flow
31. `icmp_id_entropy` - Shannon entropy of ICMP ID distribution
32. `icmp_id_variance` - Variance of ICMP IDs (numeric interpretation)
33. `icmp_id_pattern_score` - Score for ASCII/pattern encoding in IDs
34. `icmp_id_mode` - Most frequent ICMP ID in the flow
35. `icmp_id_change_count` - Number of times ICMP ID changes
36. `icmp_id_change_rate` - Rate of ICMP ID changes per packet

**ICMP Sequence Number:**
37. `icmp_seq_count` - Number of unique sequence numbers
38. `icmp_seq_min` - Minimum sequence number
39. `icmp_seq_max` - Maximum sequence number
40. `icmp_seq_range` - Range of sequence numbers (max - min)
41. `icmp_seq_mean` - Mean sequence number
42. `icmp_seq_std` - Standard deviation of sequence numbers
43. `icmp_seq_sequential_ratio` - Ratio of sequential increments (normal behavior)
44. `icmp_seq_non_sequential_count` - Number of non-sequential jumps
45. `icmp_seq_reverse_count` - Number of reverse/decreasing sequences
46. `icmp_seq_duplicate_count` - Number of duplicate sequence numbers
47. `icmp_seq_gap_count` - Number of gaps in sequence
48. `icmp_seq_entropy` - Entropy of sequence distribution
49. `icmp_seq_randomness_score` - Measure of sequence randomness

**ICMP Type and Code:**
50. `icmp_type_count` - Number of unique ICMP types
51. `icmp_code_count` - Number of unique ICMP codes
52. `icmp_type_mode` - Most frequent ICMP type
53. `icmp_code_mode` - Most frequent ICMP code
54. `icmp_type_entropy` - Entropy of ICMP type distribution
55. `icmp_echo_request_ratio` - Ratio of echo requests to total packets
56. `icmp_echo_reply_ratio` - Ratio of echo replies to total packets
57. `icmp_request_reply_ratio` - Ratio of requests to replies (should be ~1 for normal)

**TTL Analysis:**
58. `ttl_count` - Number of unique TTL values
59. `ttl_mean` - Mean TTL value
60. `ttl_std` - Standard deviation of TTL
61. `ttl_min` - Minimum TTL
62. `ttl_max` - Maximum TTL
63. `ttl_range` - Range of TTL values
64. `ttl_variance_score` - Variance score (constant TTL = normal)
65. `ttl_mode` - Most frequent TTL value
66. `ttl_anomaly_count` - Count of unusual TTL values (not 64, 128, 255)

**Checksum Analysis:**
67. `icmp_checksum_variance` - Variance in ICMP checksums
68. `icmp_checksum_entropy` - Entropy of checksum distribution
69. `icmp_checksum_anomaly_count` - Invalid/suspicious checksums

---

### **TECHNIQUE 3: FLOW BENDING


#### IP Layer Features

**IP Header Fields:**
106. `ip_version` - IP version (should be 4 for IPv4)
107. `ip_header_length_min` - Minimum IP header length
108. `ip_header_length_max` - Maximum IP header length
109. `ip_header_length_avg` - Average IP header length
110. `ip_header_length_variance` - Variance in header length (options detection)
111. `ip_header_length_unique` - Number of unique header lengths

**IP Flags:**
112. `ip_df_flag_count` - Count of Don't Fragment (DF) flags set
113. `ip_mf_flag_count` - Count of More Fragments (MF) flags set
114. `ip_df_ratio` - Ratio of packets with DF flag
115. `ip_mf_ratio` - Ratio of packets with MF flag
116. `ip_flag_variance` - Variance in flag settings

**IP Fragmentation:**
117. `fragmented_packet_count` - Number of fragmented packets
118. `fragmentation_ratio` - Ratio of fragmented to total packets
119. `fragment_offset_max` - Maximum fragment offset
120. `fragment_offset_variance` - Variance in fragment offsets
121. `unique_fragment_ids` - Number of unique fragment IDs
122. `avg_fragments_per_id` - Average fragments per fragmentation ID
123. `incomplete_fragment_count` - Count of incomplete fragment sets
124. `overlapping_fragment_count` - Count of overlapping fragments (anomaly)

**IP Options:**
125. `ip_options_present_count` - Packets with IP options set
126. `ip_options_ratio` - Ratio of packets with IP options
127. `ip_options_length_avg` - Average length of IP options field
128. `ip_options_type_count` - Number of unique IP option types
129. `ip_options_entropy` - Entropy of IP options distribution
130. `ip_timestamp_option_count` - Packets with timestamp option
131. `ip_record_route_count` - Packets with record route option
132. `ip_source_route_count` - Packets with source routing option

**IP Identification Field:**
133. `ip_id_min` - Minimum IP identification value
134. `ip_id_max` - Maximum IP identification value
135. `ip_id_range` - Range of IP IDs
136. `ip_id_sequential_ratio` - Ratio of sequential IP IDs (normal behavior)
137. `ip_id_entropy` - Entropy of IP ID distribution
138. `ip_id_randomness_score` - Randomness of IP IDs

**ToS/DSCP:**
139. `tos_count` - Number of unique ToS/DSCP values
140. `tos_mode` - Most frequent ToS value
141. `tos_variance` - Variance in ToS values
142. `tos_anomaly_count` - Count of unusual ToS settings
143. `ecn_flag_count` - Explicit Congestion Notification flags set

#### Flow Direction and Endpoints

**Source/Destination Analysis:**
144. `unique_src_ips` - Number of unique source IPs in flow
145. `unique_dst_ips` - Number of unique destination IPs in flow
146. `src_ip_entropy` - Entropy of source IP distribution
147. `dst_ip_entropy` - Entropy of destination IP distribution
148. `src_ip_change_count` - Number of source IP changes (spoofing indicator)
149. `dst_ip_change_count` - Number of destination IP changes
150. `bidirectional_flag` - Whether flow has both directions (0/1)
151. `forward_packets` - Number of forward direction packets
152. `backward_packets` - Number of backward direction packets
153. `forward_backward_ratio` - Ratio of forward to backward packets

**Port Information (if applicable):**
154. `src_port_entropy` - Entropy of source ports (not typical for ICMP)
155. `dst_port_entropy` - Entropy of destination ports

**Geographic/Network:**
156. `src_subnet_count` - Number of unique source subnets
157. `dst_subnet_count` - Number of unique destination subnets
158. `cross_subnet_flag` - Whether flow crosses subnets (0/1)

#### Flow Behavior

**Flow Statistics:**
159. `flow_pkts_per_sec` - Packets per second (flow rate)
160. `flow_bytes_per_sec` - Bytes per second (flow throughput)
161. `flow_active_time` - Total active time (excluding idle periods)
162. `flow_idle_time` - Total idle time (gaps in flow)
163. `flow_active_ratio` - Ratio of active to total duration
164. `flow_idle_count` - Number of idle periods

**Flow Pattern:**
165. `flow_symmetry_score` - Symmetry between forward/backward traffic
166. `flow_consistency_score` - Consistency of packet patterns
167. `flow_anomaly_score` - Overall anomaly score for the flow

#### Routing and Path

**Path Analysis:**
168. `ttl_hop_count_estimate` - Estimated hop count (based on TTL)
169. `ttl_consistency_score` - Consistency of TTL values (same path)
170. `path_change_indicator` - Indicator of routing path changes
171. `routing_loop_indicator` - Indicator of potential routing loops

**Network Layer:**
172. `protocol_type` - Protocol type (should be ICMP = 1)
173. `protocol_variance` - Variance if protocol changes (tunneling detection)

---

## Feature Aggregation Methods

### How to Create Flow-Level from Packet-Level Data

```python
# Group packets by flow (5-tuple or simplified for ICMP)
# For ICMP: group by (src_ip, dst_ip, icmp_id) or time windows

# Example flow grouping:
flows = df.groupby(['Source', 'Destination', 'ICMP_ID']).agg({
    # Timing features
    'Time': ['min', 'max', 'count', 'std'],
    'Time_Diff': ['mean', 'std', 'min', 'max', 'median'],
    
    # Size features
    'Length': ['sum', 'mean', 'std', 'min', 'max', 'median'],
    
    # Sequence features
    'ICMP_Seq': ['min', 'max', 'count', 'std', 'nunique'],
    
    # TTL features
    'ICMP_TTL': ['mean', 'std', 'min', 'max', 'nunique']
})

# Calculate derived features
flows['flow_duration'] = flows[('Time', 'max')] - flows[('Time', 'min')]
flows['pkts_per_sec'] = flows[('Time', 'count')] / flows['flow_duration']
flows['bytes_per_sec'] = flows[('Length', 'sum')] / flows['flow_duration']
```

---

## Priority Features by Technique

### **HIGH PRIORITY (Must Have):**

#### Time Obfuscation:
- avg_inter_arrival_time
- std_inter_arrival_time
- inter_arrival_time_variance
- burst_count
- burst_ratio
- timing_entropy

#### Header Manipulation:
- icmp_id_entropy
- icmp_seq_sequential_ratio
- icmp_seq_entropy
- packet_size_variance
- non_standard_size_ratio

#### Payload Size Covert:
- avg_packet_size
- std_packet_size
- packet_size_entropy
- non_standard_size_count
- oversized_packet_ratio

#### Flow Bending:
- ip_header_length_variance (if available)
- fragmentation_ratio (if available)
- ip_options_ratio (if available)
- unique_src_ips
- unique_dst_ips

### **MEDIUM PRIORITY (Should Have):**

- timing_skewness, timing_kurtosis
- icmp_id_change_rate
- size_time_correlation
- ip_id_entropy
- ttl_variance_score
- flow_symmetry_score

### **LOW PRIORITY (Nice to Have):**

- Autocorrelation features
- Advanced statistical moments
- Multi-dimensional correlations

---

## Feature Count Summary

| Technique | Feature Count | Priority Distribution |
|-----------|---------------|----------------------|
| **Time Obfuscation** | 29 features | High: 8, Medium: 12, Low: 9 |
| **Header Manipulation** | 40 features | High: 12, Medium: 18, Low: 10 |
| **Payload Size Covert** | 35 features | High: 8, Medium: 15, Low: 12 |
| **Flow Bending** | 69 features | High: 6, Medium: 20, Low: 43 |
| **TOTAL** | **173 features** | High: 34, Medium: 65, Low: 74 |

---

## Implementation Strategy for Your FYP

### Phase 1: Basic Flow Aggregation (Minimum Viable)
**Start with these 20 essential features:**
1. flow_duration
2. flow_packets_per_second
3. avg_inter_arrival_time
4. std_inter_arrival_time
5. burst_ratio
6. avg_packet_size
7. std_packet_size
8. packet_size_entropy
9. icmp_id_count
10. icmp_id_entropy
11. icmp_seq_sequential_ratio
12. non_standard_size_ratio
13. total_packets
14. total_bytes
15. timing_entropy
16. icmp_seq_entropy
17. unique_packet_sizes
18. max_inter_arrival_time
19. oversized_packet_ratio
20. icmp_id_change_count

### Phase 2: Enhanced Features (Better Performance)
Add 30-40 more features from the medium priority list

### Phase 3: Complete Feature Set (Best Performance)
Implement all 173 features with proper feature selection

---

## Tools and Libraries for Feature Engineering

```python
# Required libraries
import pandas as pd
import numpy as np
from scipy import stats
from sklearn.preprocessing import StandardScaler
import networkx as nx  # For flow graph features

# Feature extraction functions
def calculate_entropy(series):
    """Shannon entropy"""
    value_counts = series.value_counts()
    probabilities = value_counts / len(series)
    return -np.sum(probabilities * np.log2(probabilities + 1e-10))

def calculate_burst_ratio(time_diffs, threshold=0.0001):
    """Ratio of packets in bursts"""
    bursts = (time_diffs < threshold).sum()
    return bursts / len(time_diffs)

def calculate_sequential_ratio(seq_values):
    """Ratio of sequential increments"""
    diffs = np.diff(seq_values)
    sequential = (diffs == 1).sum()
    return sequential / len(diffs) if len(diffs) > 0 else 0
```

---

## Notes on Missing Features in Your Current Dataset

### Currently Available in Packet-Level Data:
✅ Time
✅ Source, Destination
✅ Length
✅ ICMP ID, Seq, TTL (from Info field)

### Requires Full Packet Capture (Wireshark/tcpdump):
❌ IP header length
❌ IP flags (DF, MF)
❌ Fragment offset
❌ IP options
❌ IP identification field
❌ ToS/DSCP
❌ ICMP type/code (may be in Info field)
❌ ICMP checksum
❌ Actual payload bytes

### Recommendation:
If you need flow bending features (106-173), you must:
1. Re-capture traffic with full packet details
2. Use tools: `tshark -T fields -e <field>` or `scapy`
3. Export additional IP header fields from Wireshark

---

## Final Recommendation

1. ✅ Implement all **Time Obfuscation** features (29) - 
2. ✅ Implement all **Header Manipulation** features (40) - 
3. ✅ Implement all **Payload Size Covert** features (35) - 
4. ⚠️ Implement basic **Flow Bending** features (15-20) - requires re-capture for full support

