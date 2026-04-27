**Flag:** `UMDCTF{a_little_gram_schmidt_never_hurt_anybody}`

**Category:** Misc

**Challenge author:** segal

***

## Challenge: dualflow

This AI challenge involved a lot of math. Essentially, we had to fool an anomaly detector into accepting our tampered data.

```"my trading model has two flows now! double the flows means double the robustness right?"* nc challs.umdctf.io 30303```

We were given several files to set up the environment locally: the network architecture (`flow.py`), the weights of two pre-trained models, a test input, and the server's validation logic.

### What exactly does the system do?

The system uses Normalizing Flows (RealNVP). Without getting lost in formulas, think of it as a neural network that takes complex data and transforms it into a predictable distribution.

The server runs two of these models in parallel as security guards. To bypass them, our payload had to satisfy three very strict mathematical conditions simultaneously.

In short: the tampered data had to look more "normal" to the second model than to the first, have a very high probability of being real, and maintain internal coherence.

### The vulnerability: Trial and error

Since we had access to the model weights (a textbook white-box adversarial attack), we could calculate exactly how to alter the original input by injecting minimal noise.

This is where I spent a good while struggling. First I tried using an optimizer called Adam to force my payload into shape, but it was a complete headache.

Adam accumulates momentum in its calculations. Since the mathematical landscape of this network was so volatile, the optimizer went haywire, amplified the noise, and completely destroyed the original data.

### Solution: PGD to the rescue

That is when I realized Adam was the problem. I needed to be much more subtle rather than trying to brute-force convergence.

I used a technique called PGD (Projected Gradient Descent), but focusing **only on the direction** of the error (its sign) rather than its magnitude. This way I took small, safe steps toward the solution.

I put together this script to run everything locally. One tip: I had to force-install the CPU version of PyTorch because the standard one weighs around 3GB and was blowing out the `/tmp` memory on my local Linux.

```python
import torch
import numpy as np
import base64
import io
import pwn
from flow import RealNVP

# ── 1. Load calibration and challenge parameters ──────────────────────────────
cal         = np.load("calibration.npz")
target_margin = float(cal["target_margin"])   # ~30.0
lp_thresh1    = float(cal["lp_thresh1"])      # ~932.80
band1_lo      = float(cal["band1_lo"])        # ~1367.15
band1_hi      = float(cal["band1_hi"])        # ~1595.05

x_ref   = np.load("reference_window.npy")
x_ref_t = torch.tensor(x_ref, dtype=torch.float32).unsqueeze(0)

# ── 2. Load both models in evaluation mode ────────────────────────────────────
def load_flow(name):
    d    = torch.load(name, map_location="cpu")
    flow = RealNVP(
        channels=d["channels"], window=d["window"],
        n_layers=d["n_layers"], hidden=d["hidden"]
    )
    flow.load_state_dict(d["state_dict"])
    flow.eval()
    for p in flow.parameters():
        p.requires_grad = False
    return flow

f0 = load_flow("flow_0.pt")
f1 = load_flow("flow_1.pt")

def log_prob_parts(flow, x):
    """Computes log_prior, log_det, and total log_prob for a flow."""
    z, log_det = flow.forward(x)
    log_prior  = -0.5 * (z ** 2).sum(dim=1) - 0.5 * flow.dim * np.log(2.0 * np.pi)
    return log_prior, log_det, log_prior + log_det

# ── 3. PGD with gradient sign (iterative FGSM) ───────────────────────────────
delta = torch.zeros_like(x_ref_t, requires_grad=True)
EPS   = 0.08    # Maximum attack constraint
ALPHA = 0.001   # Fixed step size per iteration

print("[*] Starting sign-based PGD optimization (no Adam)...")

for i in range(15000):
    if delta.grad is not None:
        delta.grad.zero_()

    x_sub = x_ref_t + delta

    _, _,  lp0 = log_prob_parts(f0, x_sub)
    _, ld1, lp1 = log_prob_parts(f1, x_sub)
    margin = lp1 - lp0

    # Only penalize when conditions are NOT met
    loss_margin  = torch.relu(target_margin + 1.0 - margin)
    loss_lp1     = torch.relu(lp_thresh1   + 1.0 - lp1)
    loss_ld1_lo  = torch.relu(band1_lo     + 1.0 - ld1)
    loss_ld1_hi  = torch.relu(ld1 - (band1_hi   - 1.0))

    loss = loss_margin + loss_lp1 + loss_ld1_lo + loss_ld1_hi

    if loss.item() == 0:
        print(f"\n[+] Convergence achieved at iteration {i}")
        break

    loss.backward()

    with torch.no_grad():
        delta -= ALPHA * delta.grad.sign()   # Small sign-guided steps
        delta.clamp_(-EPS, EPS)              # Keep the injection nearly invisible
    delta.requires_grad_(True)

# ── 4. Serialize and send to the server ──────────────────────────────────────
x_final = (x_ref_t + delta).detach()
x_out = x_final.squeeze(0).numpy()

buf   = io.BytesIO()
np.save(buf, x_out)
b64_payload = base64.b64encode(buf.getvalue())

print("[*] Connecting to challs.umdctf.io:30303...")
conn = pwn.remote("challs.umdctf.io", 30303)
conn.recvuntil(b"> ")
conn.sendline(b64_payload)

print("\n[+] Server response:")
print(conn.recvall().decode())
```

Since the reference input we were given was already very close to being valid, this calm approach worked perfectly. The model converged in just 2 iterations without breaking anything.

### Payload delivery

The script took our tampered tensor, serialized it, encoded it in base64, and sent it directly to the server socket using pwntools.

The remote system evaluated our data, determined that we met all constraints by the slimmest of margins, accepted the bypass, and handed us the flag.

### Flag obtained

```
UMDCTF{a_little_gram_schmidt_never_hurt_anybody}
```

## Lessons learned

* Momentum-based optimizers like Adam can destroy your payload if the model is unstable. Sometimes a simple sign-guided PGD is far more effective.
* A white-box attack does not need to alter the original data much at all; we used only a fraction of the allowed noise to fool both detectors.
* Installing the lightweight version of PyTorch (`--index-url https://download.pytorch.org/whl/cpu`) is a lifesaver when working in Linux environments with limited temporary partition memory.