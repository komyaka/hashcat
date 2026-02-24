{
  "workflow": "Recursive_Optimization",
  "shared_context": "STATUS.md",
  "agents": [
    {
      "id": "Opus-45-Lead",
      "model": "claude-4.5-opus",
      "persona": "Technical Lead / Architect",
      "goal": "Декомпозиция модулей Hashcat, проектирование математической логики и структуры данных."
    },
    {
      "id": "GPT-52-Engine",
      "model": "gpt-5.2",
      "persona": "Performance Engineer (Low-level C/OpenCL)",
      "goal": "Написание кода, оптимизация циклов, работа с SIMD и памятью GPU для максимального хэшрейта."
    },
    {
      "id": "Opus-46-Auditor",
      "model": "claude-4.6-opus",
      "persona": "Principal Security & QA (20 years exp)",
      "goal": "Глубокий аудит кода, поиск утечек памяти, проверка граничных условий и верификация скорости."
    }
  ]
}
