import * as webllm from "https://esm.run/@mlc-ai/web-llm";

console.log("Starting llm_worker.js ...");

const handler = new webllm.WebWorkerMLCEngineHandler();

self.onmessage = (msg) => {
    
    handler.onmessage(msg);
};
