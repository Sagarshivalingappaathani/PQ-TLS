# Quick Reference Card

## 🚀 Quick Start Commands

### Classic-Fork (Traditional TLS)
```bash
cd classic-fork
make clean && make
./build/tls_server &        # Terminal 1
./build/tls_client          # Terminal 2
```

### Quantum-Fork (Post-Quantum TLS)
```bash
cd quantum-fork
make clean && make
./build/tls_server &        # Terminal 1
./build/tls_client          # Terminal 2
```

## 📊 Performance at a Glance

| What | Classical | Post-Quantum | Winner |
|------|-----------|--------------|--------|
| **Speed** | 6.24 ms | **2.69 ms** | 🥇 PQ (57% faster!) |
| **Signature** | 2.50 ms | **0.51 ms** | 🥇 PQ (80% faster!) |
| **Size** | **1.8 KB** | 11.5 KB | 🥇 Classical (6x smaller) |

## 🔐 Security Comparison

| Threat | Classical | Post-Quantum |
|--------|-----------|--------------|
| **Quantum Computer** | ❌ Broken | ✅ **Safe** |
| **Current Hackers** | ✅ Safe | ✅ Safe |

## 🎯 Bottom Line

✅ **Post-quantum TLS is FASTER and QUANTUM-SAFE!**  
⚠️ Trade-off: Uses more bandwidth

## 📁 Key Files

- `classic-fork/results/client_metrics.csv` - Classical performance
- `quantum-fork/results/client_metrics.csv` - PQ performance  
- `PROJECT_SUMMARY.md` - Full analysis

## 🔍 Verify It's Working

**Look for these in quantum-fork output:**
```
✓ Key Exchange Algorithm: kyber768
Signature Size: 3293 bytes
Certificate Size: 5624 bytes
```

**If you see these numbers, Dilithium is working!** ✅
