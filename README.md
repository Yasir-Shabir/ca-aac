# CA-AAC: Context-Aware Adaptive Access Control System

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)




## Overview

**CA-AAC: Context-Aware Adaptive Access Control** is a framework for privacy preservation in Industrial Location-Based Services (ILBS). It dynamically adjusts access permissions based on context, including user location, time, device status, behavioral patterns, and threat level.

The framework combines:  
- **Rabin Logic** for formal verification of safety and liveness properties  
- **Machine Learning** for runtime threat estimation  
- **TON_IoT Dataset** for empirical validation  

**Decision Logic:**  
- Threat ≤ 0.3 → PERMIT  
- 0.3 < Threat ≤ 0.6 → CONDITIONAL  
- Threat > 0.6 → DENY  

**Performance Highlights:**  
- Accuracy: 96.08%  
- F1-Score: 97.48%  
- Security (attacks blocked): 99.45%  
- Usability (normal allowed): 85.23%  

This approach provides a secure, context-aware, and adaptive solution for access control in ILBS.


## Quick Start
```bash
# Clone repository
git clone https://github.com/Yasir-Shabir/ca-aac.git
cd ca-aac

# Install dependencies
pip install -r requirements.txt

# Run analysis
python src/ca_aac_analysis.py --dataset data/Train_Test_Network.csv
```

## Docker
```bash
# Build and run
docker-compose up
```

## Author


Muhammad Yasir Shabir  
Department of Computer Science and Information Technology,    
University of Kotli Azad Jammu and Kashmir, Kotli AJK

Zahid Mahmood  
Department of Computer Science and Information Technology,    
University of Kotli Azad Jammu and Kashmir, Kotli AJK

Hira Rasheed  
Faculty of Computer Science and Information Technology, Universiti Malaya, Kuala Lumpur, 50603, Malaysia


## Citation

If you use this work, please cite:
```bibtex
@article{yasir2025caac,
  title={A Context-Aware Adaptive Access Control Framework for Privacy Preservation in Industrial Location-Based Services},
  author={Muhammad Yasir Shabir and Zahid Mahmood and Hira Rasheed,.........},
  year={2025},
  note={Manuscript under review}
}
```



## License

MIT License
