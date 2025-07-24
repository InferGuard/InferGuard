import torch
import os
import hashlib
import safetensors
from safetensors.torch import load_file
from typing import Dict


def compute_hash(file_path: str, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def scan_tensor_stats(tensor, name: str, threshold_std=3.0) -> Dict:
    stats = {}
    mean = tensor.mean().item()
    std = tensor.std().item()
    max_val = tensor.max().item()
    min_val = tensor.min().item()
    suspicious = std > threshold_std or abs(mean) > 3.0
    stats[name] = {
        "mean": mean,
        "std": std,
        "max": max_val,
        "min": min_val,
        "suspicious": suspicious
    }
    return stats


def scan_weights(file_path: str) -> Dict:
    report = {
        "model_path": file_path,
        "hash": compute_hash(file_path),
        "format": None,
        "total_tensors": 0,
        "suspicious_tensors": [],
        "stats": {}
    }

    if file_path.endswith(".safetensors"):
        tensors = load_file(file_path)
        report["format"] = "safetensors"
    elif file_path.endswith(".pt") or file_path.endswith(".bin"):
        tensors = torch.load(file_path, map_location="cpu")
        if isinstance(tensors, dict) and "state_dict" in tensors:
            tensors = tensors["state_dict"]
        report["format"] = "torch"
    else:
        report["error"] = "Unsupported file format"
        return report

    if not isinstance(tensors, dict):
        report["error"] = "Model does not contain tensors in dict form"
        return report

    for name, tensor in tensors.items():
        if not isinstance(tensor, torch.Tensor):
            continue
        stat = scan_tensor_stats(tensor, name)
        report["stats"].update(stat)
        report["total_tensors"] += 1
        if stat[name]["suspicious"]:
            report["suspicious_tensors"].append(name)

    return report
