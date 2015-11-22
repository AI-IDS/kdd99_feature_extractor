# kdd99_feature_extractor
Utility for extraction of subset of KDD '99 features [1] from realtime network traffic or .pcap file
This utility is a part of our project at University of Bergen.

Some feature might not be calculated exactly same way as in KDD, because there was no documentation explaining the details of KDD implementation found. Algorithms are based on some articles [2][3] and observation of values in KDD dataset. 

Features in KDD should be the same as features introduced by Lee & Stolfo in their work [2].

## Features
* Subset of KDD '99 features [1]
  * Content features (columns 10-22 of KDD) are not included
* Optional extra features - IP addresses, ports, timestamp of last packet (option `-e`)

## Main components
1. Sniffer
  * Network traffic sniffer & frame parser
2. IP reassembler
  * Only IP header "summaries" 
  * Payload not reassembled (content features not extracted, it is not needed)
3. Connection/Conversation reconstructor
  * Reconstructs conversations
  * Computes intrinsic features (columns 1-9 of KDD)
4. Statistical engine
  * Computes derived features (columns 23-41 of KDD)

## Main sources of feature documentation
[1] KDD Cup 1999 Data, http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html

[2] [Lee, W. & Stolfo, S. J. (2000), 'A framework for 
onstructing features and models for intrusion detection systems', Information and System Security 3 (4) , 227-261.](http://wenke.gtisc.gatech.edu/ids-readings/lee_dmids_frmwk.pdf)

[3] [Dybey, D. & Dubey, J. (2014), 'A Survey Intrusion Detection with KDD99 Cup Dataset', International Journal of Computer Science and Information Technology Research 2 (3), 146-157.](http://www.researchpublish.com/download.php?file=A%20Survey%20Intrusion%20Detection%20with%20KDD99-403.pdf&act=book)
