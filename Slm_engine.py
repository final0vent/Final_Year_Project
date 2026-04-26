import time
from typing import List, Tuple

from transformers import AutoTokenizer
import config
import prompts


class KQLGeneratorSession:
    def __init__(self, model_id=None):
        self.base_prompt = prompts.GENERATE_IR_PROMPT
        self.model_id = model_id or config.MODEL_ID
        self.tokenizer = None
        self._pipe = None

    def _get_pipe(self):
        if self._pipe is None:
            self._pipe = config.get_pipe()
        return self._pipe

    def _get_tokenizer(self):
        if self.tokenizer is None:
            pipe = self._get_pipe()
            self.tokenizer = getattr(pipe, "tokenizer", None)
        if self.tokenizer is None:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_id, local_files_only=True)
        return self.tokenizer

    def _build_prompt_text(self, nl_prompt: str) -> Tuple[str, float]:
        system_text = self.base_prompt.replace("{nl}", nl_prompt)
        messages = [{"role": "user", "content": system_text}]

        t0 = time.perf_counter()
        prompt_text = self._get_tokenizer().apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True
        )
        t1 = time.perf_counter()
        return prompt_text, (t1 - t0) * 1000

    def generate(self, nl_prompt: str, max_new_tokens: int = 512):
        prompt_text, tokenize_ms = self._build_prompt_text(nl_prompt)
        t1 = time.perf_counter()
        out = self._get_pipe()(prompt_text, **config.get_generation_kwargs(max_new_tokens))
        t2 = time.perf_counter()

        gen = out[0]["generated_text"]

        timing = {
            "tokenize_ms": tokenize_ms,
            "inference_ms": (t2 - t1) * 1000,
            "total_ms": tokenize_ms + ((t2 - t1) * 1000),
        }

        return gen.strip(), timing

    def generate_batch(self, nl_prompts: List[str], max_new_tokens: int = 512):
        prompt_texts: List[str] = []
        tokenize_times: List[float] = []

        for nl_prompt in nl_prompts:
            prompt_text, tokenize_ms = self._build_prompt_text(nl_prompt)
            prompt_texts.append(prompt_text)
            tokenize_times.append(tokenize_ms)

        t1 = time.perf_counter()
        outputs = self._get_pipe()(
            prompt_texts,
            batch_size=len(prompt_texts),
            **config.get_generation_kwargs(max_new_tokens),
        )
        t2 = time.perf_counter()

        batch_inference_ms = (t2 - t1) * 1000
        per_item_inference_ms = batch_inference_ms / max(len(prompt_texts), 1)

        normalized_outputs = []
        for output in outputs:
            if isinstance(output, list):
                text = output[0]["generated_text"]
            else:
                text = output["generated_text"]
            normalized_outputs.append(text.strip())

        timings = [
            {
                "tokenize_ms": tokenize_ms,
                "inference_ms": per_item_inference_ms,
                "total_ms": tokenize_ms + per_item_inference_ms,
            }
            for tokenize_ms in tokenize_times
        ]

        return list(zip(normalized_outputs, timings))

    def close(self) -> None:
        self.tokenizer = None
        self._pipe = None
        config.release_pipe()
