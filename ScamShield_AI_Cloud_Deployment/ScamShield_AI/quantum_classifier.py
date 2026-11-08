"""Small experimental variational quantum classifier implemented with Qiskit.

This module uses a 4-qubit parameterized circuit and statevector simulation. It is a
teaching/research prototype, not a production fraud detector. The demo parameters are
fixed and are NOT trained on a real dataset. Replace with a properly trained VQC and
validate it against a classical baseline before reporting research results.
"""
from __future__ import annotations
import math

try:
    from qiskit import QuantumCircuit
    from qiskit.quantum_info import Statevector, SparsePauliOp
    AVAILABLE = True
except Exception:
    QuantumCircuit = None
    Statevector = None
    SparsePauliOp = None
    AVAILABLE = False


class QuantumScamClassifier:
    def __init__(self):
        self.available = AVAILABLE
        # Demo variational parameters. These are illustrative, not scientifically trained.
        self.theta = [0.35, -0.65, 0.8, 0.25]

    def circuit(self, features):
        if not self.available:
            raise RuntimeError("Qiskit is not installed")
        values = list(features[:4])
        values += [0.0] * (4 - len(values))
        qc = QuantumCircuit(4)
        # Feature map: encode four normalized classical features as rotations.
        for q, value in enumerate(values):
            qc.ry(float(value) * math.pi, q)
        # Entangling layer + variational rotations.
        qc.cx(0, 1)
        qc.cx(1, 2)
        qc.cx(2, 3)
        for q, theta in enumerate(self.theta):
            qc.ry(theta, q)
        qc.cx(3, 0)
        for q, theta in enumerate(reversed(self.theta)):
            qc.rz(theta / 2, q)
        return qc

    def predict_proba(self, features):
        """Return a bounded experimental probability from Z expectations."""
        if not self.available:
            raise RuntimeError("Qiskit is not available")
        state = Statevector.from_instruction(self.circuit(features))
        # Pauli strings are written in reverse qubit order in Qiskit.
        z0 = float(state.expectation_value(SparsePauliOp.from_list([("IIIZ", 1.0)])).real)
        z1 = float(state.expectation_value(SparsePauliOp.from_list([("IIZI", 1.0)])).real)
        z2 = float(state.expectation_value(SparsePauliOp.from_list([("IZII", 1.0)])).real)
        z3 = float(state.expectation_value(SparsePauliOp.from_list([("ZIII", 1.0)])).real)
        # Map mean measurement expectation [-1, 1] into [0, 1].
        mean_z = (z0 + z1 + z2 + z3) / 4.0
        return float(max(0.0, min(1.0, (1.0 - mean_z) / 2.0)))
