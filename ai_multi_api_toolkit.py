"""
AI Multi-API Toolkit 2026
=========================
สคริปต์เชื่อมต่อกับ API ของ AI หลายตัวพร้อมกัน
รองรับ: OpenAI, Anthropic (Claude), Google Gemini, DeepSeek, Mistral

การติดตั้ง:
    pip install openai anthropic google-generativeai httpx

การใช้งาน:
    1. ตั้งค่า API Key ใน environment variables หรือไฟล์ .env
    2. import แล้วใช้งานได้เลย

ตัวอย่าง:
    from ai_multi_api_toolkit import AIToolkit

    toolkit = AIToolkit()

    # ใช้ทีละตัว
    response = toolkit.chat("OpenAI", "สวัสดี อธิบาย AI ให้หน่อย")

    # ใช้หลายตัวพร้อมกัน แล้วเปรียบเทียบ
    results = toolkit.compare_all("อธิบาย Quantum Computing แบบเข้าใจง่าย")

    # หา AI ที่ถูกที่สุดสำหรับงาน
    cheapest = toolkit.find_cheapest("ช่วยเขียนบทความ 500 คำ")
"""

import os
import json
import time
import asyncio
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

# ======================================================
# CONFIG & PRICING
# ======================================================

@dataclass
class ModelConfig:
    """การตั้งค่าของแต่ละ AI Model"""
    provider: str
    model_id: str
    display_name: str
    input_price_per_1m: float   # $/1M input tokens
    output_price_per_1m: float  # $/1M output tokens
    max_context: int            # max context window
    strengths: list = field(default_factory=list)

# ราคา API อัปเดต มีนาคม 2026
MODELS = {
    # === OpenAI ===
    "gpt-5.2": ModelConfig("OpenAI", "gpt-5.2", "GPT-5.2", 1.75, 14.00, 128000,
        ["งานทั่วไป", "วิเคราะห์ธุรกิจ", "สนทนา"]),
    "gpt-5-nano": ModelConfig("OpenAI", "gpt-5-nano", "GPT-5 Nano", 0.05, 0.40, 128000,
        ["งานเบา", "ประหยัด", "ตอบเร็ว"]),

    # === Anthropic ===
    "claude-opus-4-6": ModelConfig("Anthropic", "claude-opus-4-6", "Claude Opus 4.6", 5.00, 25.00, 200000,
        ["เขียน", "วิจัย", "โค้ด", "วิเคราะห์เชิงลึก"]),
    "claude-sonnet-4-6": ModelConfig("Anthropic", "claude-sonnet-4-6", "Claude Sonnet 4.6", 3.00, 15.00, 200000,
        ["คุ้มค่า", "เขียน", "โค้ด"]),
    "claude-haiku-4-5": ModelConfig("Anthropic", "claude-haiku-4-5-20251001", "Claude Haiku 4.5", 0.80, 4.00, 200000,
        ["เร็ว", "ประหยัด"]),

    # === Google ===
    "gemini-2.5-pro": ModelConfig("Google", "gemini-2.5-pro-latest", "Gemini 2.5 Pro", 2.00, 12.00, 1000000,
        ["context ยาว", "multimodal", "คุ้มค่า"]),
    "gemini-2.0-flash": ModelConfig("Google", "gemini-2.0-flash", "Gemini 2.0 Flash", 0.075, 0.30, 1000000,
        ["ถูกมาก", "เร็ว"]),

    # === DeepSeek ===
    "deepseek-v3": ModelConfig("DeepSeek", "deepseek-chat", "DeepSeek V3.2", 0.28, 0.42, 128000,
        ["ถูกที่สุด", "โค้ด", "คณิตศาสตร์"]),

    # === Mistral ===
    "mistral-large": ModelConfig("Mistral", "mistral-large-latest", "Mistral Large 2", 2.00, 6.00, 128000,
        ["EU-based", "หลายภาษา", "คุ้มค่า"]),
}


# ======================================================
# API CLIENTS
# ======================================================

class OpenAIClient:
    """เชื่อมต่อ OpenAI API"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.client = None

    def _ensure_client(self):
        if not self.client:
            try:
                from openai import OpenAI
                self.client = OpenAI(api_key=self.api_key)
            except ImportError:
                raise ImportError("ติดตั้ง openai ก่อน: pip install openai")

    def chat(self, model_id: str, message: str, system: str = "", **kwargs) -> dict:
        self._ensure_client()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": message})

        start = time.time()
        response = self.client.chat.completions.create(
            model=model_id, messages=messages,
            max_tokens=kwargs.get("max_tokens", 4096),
            temperature=kwargs.get("temperature", 0.7),
        )
        elapsed = time.time() - start

        return {
            "text": response.choices[0].message.content,
            "input_tokens": response.usage.prompt_tokens,
            "output_tokens": response.usage.completion_tokens,
            "time_seconds": round(elapsed, 2),
            "model": model_id,
        }


class AnthropicClient:
    """เชื่อมต่อ Anthropic (Claude) API"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.client = None

    def _ensure_client(self):
        if not self.client:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError("ติดตั้ง anthropic ก่อน: pip install anthropic")

    def chat(self, model_id: str, message: str, system: str = "", **kwargs) -> dict:
        self._ensure_client()

        start = time.time()
        response = self.client.messages.create(
            model=model_id,
            max_tokens=kwargs.get("max_tokens", 4096),
            system=system if system else "You are a helpful assistant.",
            messages=[{"role": "user", "content": message}],
            temperature=kwargs.get("temperature", 0.7),
        )
        elapsed = time.time() - start

        return {
            "text": response.content[0].text,
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "time_seconds": round(elapsed, 2),
            "model": model_id,
        }


class GeminiClient:
    """เชื่อมต่อ Google Gemini API"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        self.model = None

    def chat(self, model_id: str, message: str, system: str = "", **kwargs) -> dict:
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError("ติดตั้ง google-generativeai ก่อน: pip install google-generativeai")

        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel(
            model_id,
            system_instruction=system if system else None,
        )

        start = time.time()
        response = model.generate_content(
            message,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=kwargs.get("max_tokens", 4096),
                temperature=kwargs.get("temperature", 0.7),
            ),
        )
        elapsed = time.time() - start

        usage = response.usage_metadata
        return {
            "text": response.text,
            "input_tokens": getattr(usage, 'prompt_token_count', 0),
            "output_tokens": getattr(usage, 'candidates_token_count', 0),
            "time_seconds": round(elapsed, 2),
            "model": model_id,
        }


class DeepSeekClient:
    """เชื่อมต่อ DeepSeek API (OpenAI-compatible)"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("DEEPSEEK_API_KEY")
        self.client = None

    def _ensure_client(self):
        if not self.client:
            try:
                from openai import OpenAI
                self.client = OpenAI(
                    api_key=self.api_key,
                    base_url="https://api.deepseek.com"
                )
            except ImportError:
                raise ImportError("ติดตั้ง openai ก่อน: pip install openai")

    def chat(self, model_id: str, message: str, system: str = "", **kwargs) -> dict:
        self._ensure_client()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": message})

        start = time.time()
        response = self.client.chat.completions.create(
            model=model_id, messages=messages,
            max_tokens=kwargs.get("max_tokens", 4096),
            temperature=kwargs.get("temperature", 0.7),
        )
        elapsed = time.time() - start

        return {
            "text": response.choices[0].message.content,
            "input_tokens": response.usage.prompt_tokens,
            "output_tokens": response.usage.completion_tokens,
            "time_seconds": round(elapsed, 2),
            "model": model_id,
        }


class MistralClient:
    """เชื่อมต่อ Mistral API (OpenAI-compatible)"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("MISTRAL_API_KEY")
        self.client = None

    def _ensure_client(self):
        if not self.client:
            try:
                from openai import OpenAI
                self.client = OpenAI(
                    api_key=self.api_key,
                    base_url="https://api.mistral.ai/v1"
                )
            except ImportError:
                raise ImportError("ติดตั้ง openai ก่อน: pip install openai")

    def chat(self, model_id: str, message: str, system: str = "", **kwargs) -> dict:
        self._ensure_client()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": message})

        start = time.time()
        response = self.client.chat.completions.create(
            model=model_id, messages=messages,
            max_tokens=kwargs.get("max_tokens", 4096),
            temperature=kwargs.get("temperature", 0.7),
        )
        elapsed = time.time() - start

        return {
            "text": response.choices[0].message.content,
            "input_tokens": response.usage.prompt_tokens,
            "output_tokens": response.usage.completion_tokens,
            "time_seconds": round(elapsed, 2),
            "model": model_id,
        }


# ======================================================
# MAIN TOOLKIT
# ======================================================

class AIToolkit:
    """
    เครื่องมือหลักสำหรับเชื่อมต่อ AI หลายตัว

    ตัวอย่างการใช้งาน:
        toolkit = AIToolkit()

        # ส่งข้อความไปยัง AI ตัวเดียว
        result = toolkit.chat("claude-sonnet-4-6", "สวัสดี")
        print(result["text"])

        # เปรียบเทียบหลายตัว
        results = toolkit.compare_all("อธิบาย AI ให้หน่อย")
        for r in results:
            print(f"{r['model']}: {r['text'][:100]}...")
    """

    def __init__(self, keys: Optional[dict] = None):
        keys = keys or {}
        self.clients = {
            "OpenAI": OpenAIClient(keys.get("openai")),
            "Anthropic": AnthropicClient(keys.get("anthropic")),
            "Google": GeminiClient(keys.get("google")),
            "DeepSeek": DeepSeekClient(keys.get("deepseek")),
            "Mistral": MistralClient(keys.get("mistral")),
        }

    def list_models(self) -> list:
        """แสดงรายการ model ทั้งหมดพร้อมราคา"""
        result = []
        for key, m in MODELS.items():
            result.append({
                "key": key,
                "name": m.display_name,
                "provider": m.provider,
                "input_price": f"${m.input_price_per_1m}/1M",
                "output_price": f"${m.output_price_per_1m}/1M",
                "context": f"{m.max_context:,}",
                "strengths": m.strengths,
            })
        return result

    def chat(self, model_key: str, message: str, system: str = "", **kwargs) -> dict:
        """
        ส่งข้อความไปยัง AI model ที่ระบุ

        Args:
            model_key: ชื่อ model เช่น "claude-sonnet-4-6", "gpt-5.2"
            message: ข้อความที่ต้องการส่ง
            system: system prompt (ถ้ามี)

        Returns:
            dict: {"text", "input_tokens", "output_tokens", "time_seconds", "cost_usd", "model"}
        """
        if model_key not in MODELS:
            raise ValueError(f"ไม่พบ model '{model_key}'. ใช้ list_models() เพื่อดูรายการ")

        config = MODELS[model_key]
        client = self.clients.get(config.provider)
        if not client:
            raise ValueError(f"ไม่พบ client สำหรับ provider '{config.provider}'")

        result = client.chat(config.model_id, message, system, **kwargs)

        # คำนวณค่าใช้จ่าย
        cost = (
            (result["input_tokens"] / 1_000_000) * config.input_price_per_1m +
            (result["output_tokens"] / 1_000_000) * config.output_price_per_1m
        )
        result["cost_usd"] = round(cost, 6)
        result["display_name"] = config.display_name

        return result

    def compare(self, model_keys: list, message: str, system: str = "", **kwargs) -> list:
        """
        เปรียบเทียบผลลัพธ์จากหลาย model

        Args:
            model_keys: รายการ model เช่น ["claude-sonnet-4-6", "gpt-5.2"]
            message: ข้อความที่ต้องการส่ง

        Returns:
            list[dict]: ผลลัพธ์จากแต่ละ model
        """
        results = []
        for key in model_keys:
            try:
                result = self.chat(key, message, system, **kwargs)
                result["status"] = "success"
                results.append(result)
            except Exception as e:
                results.append({
                    "model": key,
                    "status": "error",
                    "error": str(e),
                })

        return sorted(results, key=lambda x: x.get("cost_usd", 999))

    def compare_all(self, message: str, system: str = "", **kwargs) -> list:
        """เปรียบเทียบทุก model ที่มี API key"""
        available = []
        for key, config in MODELS.items():
            provider = config.provider
            client = self.clients.get(provider)
            if client and getattr(client, 'api_key', None):
                available.append(key)

        if not available:
            raise ValueError("ไม่พบ API key ใดเลย กรุณาตั้งค่า environment variables")

        return self.compare(available, message, system, **kwargs)

    def find_cheapest(self, message: str, system: str = "", model_keys: Optional[list] = None, **kwargs) -> dict:
        """หา model ที่ถูกที่สุดสำหรับงานนี้"""
        keys = model_keys or list(MODELS.keys())
        results = self.compare(keys, message, system, **kwargs)
        success = [r for r in results if r.get("status") == "success"]
        if not success:
            raise ValueError("ไม่มี model ใดตอบสำเร็จ")
        return min(success, key=lambda x: x["cost_usd"])

    def estimate_cost(self, model_key: str, input_tokens: int, output_tokens: int) -> float:
        """คำนวณค่าใช้จ่ายโดยประมาณ"""
        if model_key not in MODELS:
            raise ValueError(f"ไม่พบ model '{model_key}'")
        config = MODELS[model_key]
        return round(
            (input_tokens / 1_000_000) * config.input_price_per_1m +
            (output_tokens / 1_000_000) * config.output_price_per_1m,
            6
        )

    def pricing_table(self) -> str:
        """แสดงตารางราคาแบบสวยงาม"""
        lines = [
            f"{'Model':<25} {'Input $/1M':<12} {'Output $/1M':<12} {'Context':<12} {'Provider'}",
            "-" * 80,
        ]
        for key, m in sorted(MODELS.items(), key=lambda x: x[1].input_price_per_1m):
            lines.append(
                f"{m.display_name:<25} ${m.input_price_per_1m:<10.3f} ${m.output_price_per_1m:<10.2f} {m.max_context:>10,}  {m.provider}"
            )
        return "\n".join(lines)


# ======================================================
# QUICK START
# ======================================================

def quick_demo():
    """แสดงตัวอย่างการใช้งานเบื้องต้น"""
    toolkit = AIToolkit()

    print("=" * 60)
    print("  AI Multi-API Toolkit 2026")
    print("=" * 60)
    print()

    # แสดงตารางราคา
    print(toolkit.pricing_table())
    print()

    # แสดงรายการ model
    print("\nModels ที่รองรับ:")
    for m in toolkit.list_models():
        print(f"  - {m['key']}: {m['name']} ({m['provider']}) | {m['input_price']} in / {m['output_price']} out")

    # ประมาณค่าใช้จ่าย
    print("\n\nตัวอย่างการประมาณค่าใช้จ่าย (1000 input + 500 output tokens):")
    for key in MODELS:
        cost = toolkit.estimate_cost(key, 1000, 500)
        print(f"  {MODELS[key].display_name:<25} ${cost:.6f}")

    print("\n\nพร้อมใช้งาน! ตั้งค่า API keys แล้วเริ่มได้เลย:")
    print('  export OPENAI_API_KEY="sk-..."')
    print('  export ANTHROPIC_API_KEY="sk-ant-..."')
    print('  export GOOGLE_API_KEY="AI..."')
    print('  export DEEPSEEK_API_KEY="sk-..."')
    print('  export MISTRAL_API_KEY="..."')


if __name__ == "__main__":
    quick_demo()
