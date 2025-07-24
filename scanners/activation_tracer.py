import torch
from torch import nn
from typing import Dict, List, Any
from collections import defaultdict

class ActivationTracer:
    def __init__(self, model: nn.Module, layers: List[str]):
        self.model = model
        self.layers = layers
        self.hooks = []
        self.activations = defaultdict(list)

    def _hook_fn(self, name):
        def hook(module, input, output):
            if isinstance(output, torch.Tensor):
                self.activations[name].append(output.detach().cpu())
        return hook

    def register_hooks(self):
        for name, module in self.model.named_modules():
            if any(layer in name for layer in self.layers):
                self.hooks.append(module.register_forward_hook(self._hook_fn(name)))

    def clear_hooks(self):
        for hook in self.hooks:
            hook.remove()
        self.hooks = []

    def clear_activations(self):
        self.activations.clear()

    def trace(self, input_tensor: torch.Tensor) -> Dict[str, Any]:
        self.clear_activations()
        self.register_hooks()
        with torch.no_grad():
            _ = self.model(input_tensor)
        self.clear_hooks()
        stats = {}
        for name, acts in self.activations.items():
            tensor = torch.cat(acts, dim=0)
            stats[name] = {
                "mean": tensor.mean().item(),
                "std": tensor.std().item(),
                "max": tensor.max().item(),
                "min": tensor.min().item()
            }
        return stats
