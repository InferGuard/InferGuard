import gradio as gr
import torch
import mlflow.pytorch
from scanners.prompt_scanner import scan_prompt
from scanners.output_scanner import scan_output
from scanners.weight_scanner import scan_weights
from scanners.activation_tracer import ActivationTracer

import tempfile
from transformers import AutoTokenizer

loaded_model = None
tokenizer = None

def load_mlflow_model(path):
    global loaded_model
    loaded_model = mlflow.pytorch.load_model(path)
    return f"✅ Loaded MLflow model from {path}"

def upload_and_load_model(file):
    global loaded_model
    temp_path = tempfile.NamedTemporaryFile(delete=False).name
    with open(temp_path, "wb") as f:
        f.write(file.read())
    loaded_model = torch.load(temp_path, map_location="cpu")
    return f"✅ Uploaded and loaded model from: {file.name}"

def trace_activations(prompt_text):
    if not loaded_model:
        return "⚠️ Model not loaded."
    if not tokenizer:
        return "⚠️ Tokenizer not loaded."
    inputs = tokenizer(prompt_text, return_tensors="pt")
    tracer = ActivationTracer(loaded_model, layers=["transformer", "mlp", "attn", "linear"])
    stats = tracer.trace(inputs["input_ids"])
    return stats

with gr.Blocks(title="🛡️ NeuroFence LLM Threat Scanner") as demo:
    gr.Markdown("## 🔍 LLM Prompt & Model Security Scanner")

    with gr.Tab("Prompt Scan"):
        prompt_box = gr.Textbox(label="Prompt", lines=4)
        response_box = gr.Textbox(label="LLM Output (optional)", lines=4)
        scan_btn = gr.Button("🔎 Scan")
        result = gr.Textbox(label="Threat Report")

        def scan(prompt, output):
            p_result = scan_prompt(prompt)
            o_result = scan_output(output or "")
            alerts = p_result["alerts"] + o_result["alerts"]
            return "\n".join(alerts)

        scan_btn.click(scan, [prompt_box, response_box], result)

    with gr.Tab("Upload Model"):
        model_file = gr.File(label="Upload .pt / .bin / .safetensors")
        model_scan_result = gr.Textbox(label="Model Scan Result")
        model_file.upload(fn=scan_weights, inputs=model_file, outputs=model_scan_result)

    with gr.Tab("MLflow Load"):
        mlflow_path = gr.Textbox(label="MLflow Model URI (e.g. ./mlruns/0/...)")
        mlflow_btn = gr.Button("Load Model")
        mlflow_status = gr.Textbox(label="MLflow Load Result")
        mlflow_btn.click(load_mlflow_model, mlflow_path, mlflow_status)

    with gr.Tab("Activation Trace"):
        trace_input = gr.Textbox(label="Prompt")
        trace_btn = gr.Button("🧠 Trace Activations")
        trace_out = gr.Textbox(label="Activation Stats")
        trace_btn.click(fn=trace_activations, inputs=trace_input, outputs=trace_out)

demo.launch()
