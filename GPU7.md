# Руководство по оптимизации GPU для режимов Brainwallet (35900-35904)

## Оглавление
- [Введение](#введение)
- [Вариант 1: Риг из 7x AMD Sapphire Nitro+ RX 580 8GB](#вариант-1-риг-из-7x-amd-sapphire-nitro-rx-580-8gb)
- [Вариант 2: Одиночная карта GeForce RTX 3050 6GB](#вариант-2-одиночная-карта-geforce-rtx-3050-6gb)
- [Общие рекомендации по оптимизации](#общие-рекомендации-по-оптимизации)

---

## Введение

Данное руководство содержит оптимальные параметры запуска hashcat для режимов атаки на Brainwallet-кошельки (Bitcoin и Ethereum):

- **35900** — Bitcoin Brainwallet (SHA-256)
- **35901** — Bitcoin Brainwallet (SHA3-256)
- **35902** — Ethereum Brainwallet (Keccak-256)
- **35903** — Ethereum Brainwallet (SHA-256)
- **35904** — Ethereum Brainwallet (SHA3-256)

Каждый из этих режимов включает:
1. Хеширование парольной фразы (SHA-256, SHA3-256 или Keccak-256)
2. Вычисление точки на эллиптической кривой secp256k1 (скалярное умножение)
3. Деривацию адреса кошелька из публичного ключа

Эти операции требуют значительных вычислительных ресурсов GPU, особенно операция скалярного умножения на кривой secp256k1.

---

## Вариант 1: Риг из 7x AMD Sapphire Nitro+ RX 580 8GB

### Характеристики оборудования

| Параметр | Значение |
|----------|----------|
| **Модель GPU** | AMD Sapphire Nitro+ RX 580 8GB |
| **Количество карт** | 7 |
| **Архитектура** | GCN 4-го поколения (Polaris 20) |
| **Compute Units** | 36 на карту (252 всего) |
| **Stream Processors** | 2304 на карту (16128 всего) |
| **Видеопамять** | 8 GB GDDR5 на карту (56 GB суммарно) |
| **Пропускная способность памяти** | 256 GB/s на карту |
| **TDP** | 185W на карту (1295W суммарно) |
| **Backend** | OpenCL 2.0 |
| **Driver** | ROCm 5.x или AMD Adrenalin |

### Общие параметры для всех режимов (7 GPU)

```bash
--backend-devices 1,2,3,4,5,6,7   # Использовать все 7 GPU
-O                                 # Включить оптимизации ядра
--opencl-device-types 1            # Использовать только GPU устройства
```

### Режим 35900 — Bitcoin Brainwallet (SHA-256)

#### Максимальная скорость

```bash
./hashcat -m 35900 -a 0 bitcoin_addresses.txt wordlist.txt \
  --backend-devices 1,2,3,4,5,6,7 \
  -O \
  -w 4 \
  -n 512 \
  --kernel-accel 128 \
  --kernel-loops 256 \
  --kernel-threads 64
```

**Параметры:**
- `-w 4` — максимальная нагрузка (Desktop frozen)
- `-n 512` — количество задач на CU
- `--kernel-accel 128` — ускорение ядра
- `--kernel-loops 256` — количество итераций в ядре
- `--kernel-threads 64` — потоков на рабочую группу

**Ожидаемая производительность:** ~150-170 MH/s суммарно (~21-24 MH/s на карту)

**Потребление энергии:** ~1300-1400W

#### Стабильный режим (долгосрочная работа)

```bash
./hashcat -m 35900 -a 0 bitcoin_addresses.txt wordlist.txt \
  --backend-devices 1,2,3,4,5,6,7 \
  -O \
  -w 3 \
  -n 256 \
  --kernel-accel 64 \
  --kernel-loops 128 \
  --kernel-threads 32 \
  --hwmon-temp-abort 85
```

**Параметры:**
- `-w 3` — высокая нагрузка (Desktop responsive)
- Уменьшенные значения для снижения температуры
- `--hwmon-temp-abort 85` — остановка при температуре выше 85°C

**Ожидаемая производительность:** ~130-145 MH/s суммарно (~18-21 MH/s на карту)

**Потребление энергии:** ~1150-1250W

---

### Режим 35901 — Bitcoin Brainwallet (SHA3-256)

SHA3-256 более вычислительно затратен, чем SHA-256.

#### Максимальная скорость

```bash
./hashcat -m 35901 -a 0 bitcoin_addresses.txt wordlist.txt \
  --backend-devices 1,2,3,4,5,6,7 \
  -O \
  -w 4 \
  -n 384 \
  --kernel-accel 96 \
  --kernel-loops 256 \
  --kernel-threads 64
```

**Ожидаемая производительность:** ~120-135 MH/s суммарно (~17-19 MH/s на карту)

**Потребление энергии:** ~1300-1400W

#### Стабильный режим

```bash
./hashcat -m 35901 -a 0 bitcoin_addresses.txt wordlist.txt \
  --backend-devices 1,2,3,4,5,6,7 \
  -O \
  -w 3 \
  -n 256 \
  --kernel-accel 64 \
  --kernel-loops 128 \
  --kernel-threads 32 \
  --hwmon-temp-abort 85
```

**Ожидаемая производительность:** ~105-120 MH/s суммарно (~15-17 MH/s на карту)

**Потребление энергии:** ~1150-1250W

---

### Режим 35902 — Ethereum Brainwallet (Keccak-256)

Keccak-256 (оригинальный Keccak, не SHA3) часто быстрее SHA3-256.

#### Максимальная скорость

```bash
./hashcat -m 35902 -a 0 ethereum_addresses.txt wordlist.txt \
  --backend-devices 1,2,3,4,5,6,7 \
  -O \
  -w 4 \
  -n 512 \
  --kernel-accel 128 \
  --kernel-loops 256 \
  --kernel-threads 64
```

**Ожидаемая производительность:** ~140-160 MH/s суммарно (~20-23 MH/s на карту)

**Потребление энергии:** ~1300-1400W

#### Стабильный режим

```bash
./hashcat -m 35902 -a 0 ethereum_addresses.txt wordlist.txt \
  --backend-devices 1,2,3,4,5,6,7 \
  -O \
  -w 3 \
  -n 256 \
  --kernel-accel 64 \
  --kernel-loops 128 \
  --kernel-threads 32 \
  --hwmon-temp-abort 85
```

**Ожидаемая производительность:** ~120-140 MH/s суммарно (~17-20 MH/s на карту)

**Потребление энергии:** ~1150-1250W

---

### Режим 35903 — Ethereum Brainwallet (SHA-256)

Производительность аналогична режиму 35900 (Bitcoin SHA-256).

#### Максимальная скорость

```bash
./hashcat -m 35903 -a 0 ethereum_addresses.txt wordlist.txt \
  --backend-devices 1,2,3,4,5,6,7 \
  -O \
  -w 4 \
  -n 512 \
  --kernel-accel 128 \
  --kernel-loops 256 \
  --kernel-threads 64
```

**Ожидаемая производительность:** ~150-170 MH/s суммарно (~21-24 MH/s на карту)

**Потребление энергии:** ~1300-1400W

#### Стабильный режим

```bash
./hashcat -m 35903 -a 0 ethereum_addresses.txt wordlist.txt \
  --backend-devices 1,2,3,4,5,6,7 \
  -O \
  -w 3 \
  -n 256 \
  --kernel-accel 64 \
  --kernel-loops 128 \
  --kernel-threads 32 \
  --hwmon-temp-abort 85
```

**Ожидаемая производительность:** ~130-145 MH/s суммарно (~18-21 MH/s на карту)

**Потребление энергии:** ~1150-1250W

---

### Режим 35904 — Ethereum Brainwallet (SHA3-256)

Производительность аналогична режиму 35901 (Bitcoin SHA3-256).

#### Максимальная скорость

```bash
./hashcat -m 35904 -a 0 ethereum_addresses.txt wordlist.txt \
  --backend-devices 1,2,3,4,5,6,7 \
  -O \
  -w 4 \
  -n 384 \
  --kernel-accel 96 \
  --kernel-loops 256 \
  --kernel-threads 64
```

**Ожидаемая производительность:** ~120-135 MH/s суммарно (~17-19 MH/s на карту)

**Потребление энергии:** ~1300-1400W

#### Стабильный режим

```bash
./hashcat -m 35904 -a 0 ethereum_addresses.txt wordlist.txt \
  --backend-devices 1,2,3,4,5,6,7 \
  -O \
  -w 3 \
  -n 256 \
  --kernel-accel 64 \
  --kernel-loops 128 \
  --kernel-threads 32 \
  --hwmon-temp-abort 85
```

**Ожидаемая производительность:** ~105-120 MH/s суммарно (~15-17 MH/s на карту)

**Потребление энергии:** ~1150-1250W

---

### Рекомендации по охлаждению и энергопотреблению (7x RX 580)

#### Охлаждение

1. **Открытая стойка (mining rig frame)**
   - Обеспечить расстояние между картами не менее 7-10 см
   - Использовать райзеры PCIe для лучшей циркуляции воздуха

2. **Активное охлаждение помещения**
   - Рекомендуется кондиционер или хорошая вентиляция
   - Температура в помещении не должна превышать 25-27°C
   - Приточно-вытяжная вентиляция: минимум 500-700 м³/ч

3. **Настройка вентиляторов GPU**
   ```bash
   # Ручное управление вентиляторами (через amdgpu-pro или rocm-smi)
   # Установить скорость 70-80% для стабильной работы
   rocm-smi --setfan 75 --device 0
   rocm-smi --setfan 75 --device 1
   # ... для всех 7 карт
   ```

4. **Целевые температуры**
   - **Максимальный режим:** 70-80°C (допустимо)
   - **Стабильный режим:** 60-70°C (оптимально)
   - **Критическая температура:** 85°C (авто-остановка через `--hwmon-temp-abort`)

5. **Мониторинг**
   ```bash
   # Постоянный мониторинг температур всех карт
   watch -n 5 'rocm-smi -t'
   ```

#### Энергопотребление

1. **Блок питания (PSU)**
   - Минимальная мощность: **1600W** (80+ Gold или лучше)
   - Рекомендуется: **1800-2000W** для запаса
   - Возможна конфигурация из 2 блоков питания по 1000W (с синхронизатором)

2. **Undervolting (снижение напряжения)**
   - RX 580 хорошо поддаётся undervolting
   - Можно снизить TDP с 185W до ~130-150W на карту с минимальной потерей производительности
   ```bash
   # Пример с amdgpu-pro (требуется root)
   echo "manual" > /sys/class/drm/card0/device/power_dpm_force_performance_level
   echo "5 850" > /sys/class/drm/card0/device/pp_od_clk_voltage
   # Повторить для всех карт
   ```
   - С undervolting: ~1000-1100W суммарно (экономия ~200-300W)

3. **Электрическая безопасность**
   - Использовать качественные кабели питания
   - Не перегружать одну розетку/линию более чем на 80% её номинала
   - Для 1800W нужна линия минимум 220V × 10A = 2200VA

4. **Стоимость электроэнергии**
   - При тарифе 5 руб/кWh:
     - Максимальный режим (1400W): ~50 руб/сутки, ~1500 руб/месяц
     - Стабильный режим (1200W): ~43 руб/сутки, ~1300 руб/месяц
     - С undervolting (1000W): ~36 руб/сутки, ~1080 руб/месяц

---

## Вариант 2: Одиночная карта GeForce RTX 3050 6GB

### Характеристики оборудования

| Параметр | Значение |
|----------|----------|
| **Модель GPU** | NVIDIA GeForce RTX 3050 6GB |
| **Архитектура** | Ampere (GA107) |
| **CUDA Cores** | 2304 |
| **Tensor Cores** | 72 (3-го поколения) |
| **RT Cores** | 18 (2-го поколения) |
| **Видеопамять** | 6 GB GDDR6 |
| **Пропускная способность памяти** | 168 GB/s |
| **TDP** | 70W (низкопрофильные модели) / 130W (стандарт) |
| **Backend** | CUDA 11.x+ |
| **Compute Capability** | 8.6 |

### Общие параметры для RTX 3050

```bash
--backend-devices 1   # Использовать первую (единственную) GPU
-O                     # Включить оптимизации ядра
```

### Режим 35900 — Bitcoin Brainwallet (SHA-256)

#### Максимальная скорость

```bash
./hashcat -m 35900 -a 0 bitcoin_addresses.txt wordlist.txt \
  --backend-devices 1 \
  -O \
  -w 4 \
  -n 256 \
  --kernel-accel 64 \
  --kernel-loops 256 \
  --kernel-threads 128
```

**Параметры:**
- `-w 4` — максимальная нагрузка
- `-n 256` — количество задач
- `--kernel-accel 64` — ускорение ядра
- `--kernel-loops 256` — итераций в ядре
- `--kernel-threads 128` — потоков на блок (оптимально для Ampere)

**Ожидаемая производительность:** ~35-42 MH/s

**Потребление энергии:** ~110-130W (в зависимости от модели)

#### Стабильный режим

```bash
./hashcat -m 35900 -a 0 bitcoin_addresses.txt wordlist.txt \
  --backend-devices 1 \
  -O \
  -w 3 \
  -n 128 \
  --kernel-accel 32 \
  --kernel-loops 128 \
  --kernel-threads 64 \
  --hwmon-temp-abort 80
```

**Ожидаемая производительность:** ~30-36 MH/s

**Потребление энергии:** ~90-110W

---

### Режим 35901 — Bitcoin Brainwallet (SHA3-256)

#### Максимальная скорость

```bash
./hashcat -m 35901 -a 0 bitcoin_addresses.txt wordlist.txt \
  --backend-devices 1 \
  -O \
  -w 4 \
  -n 192 \
  --kernel-accel 48 \
  --kernel-loops 256 \
  --kernel-threads 128
```

**Ожидаемая производительность:** ~28-34 MH/s

**Потребление энергии:** ~110-130W

#### Стабильный режим

```bash
./hashcat -m 35901 -a 0 bitcoin_addresses.txt wordlist.txt \
  --backend-devices 1 \
  -O \
  -w 3 \
  -n 128 \
  --kernel-accel 32 \
  --kernel-loops 128 \
  --kernel-threads 64 \
  --hwmon-temp-abort 80
```

**Ожидаемая производительность:** ~24-30 MH/s

**Потребление энергии:** ~90-110W

---

### Режим 35902 — Ethereum Brainwallet (Keccak-256)

#### Максимальная скорость

```bash
./hashcat -m 35902 -a 0 ethereum_addresses.txt wordlist.txt \
  --backend-devices 1 \
  -O \
  -w 4 \
  -n 256 \
  --kernel-accel 64 \
  --kernel-loops 256 \
  --kernel-threads 128
```

**Ожидаемая производительность:** ~32-40 MH/s

**Потребление энергии:** ~110-130W

#### Стабильный режим

```bash
./hashcat -m 35902 -a 0 ethereum_addresses.txt wordlist.txt \
  --backend-devices 1 \
  -O \
  -w 3 \
  -n 128 \
  --kernel-accel 32 \
  --kernel-loops 128 \
  --kernel-threads 64 \
  --hwmon-temp-abort 80
```

**Ожидаемая производительность:** ~28-34 MH/s

**Потребление энергии:** ~90-110W

---

### Режим 35903 — Ethereum Brainwallet (SHA-256)

#### Максимальная скорость

```bash
./hashcat -m 35903 -a 0 ethereum_addresses.txt wordlist.txt \
  --backend-devices 1 \
  -O \
  -w 4 \
  -n 256 \
  --kernel-accel 64 \
  --kernel-loops 256 \
  --kernel-threads 128
```

**Ожидаемая производительность:** ~35-42 MH/s

**Потребление энергии:** ~110-130W

#### Стабильный режим

```bash
./hashcat -m 35903 -a 0 ethereum_addresses.txt wordlist.txt \
  --backend-devices 1 \
  -O \
  -w 3 \
  -n 128 \
  --kernel-accel 32 \
  --kernel-loops 128 \
  --kernel-threads 64 \
  --hwmon-temp-abort 80
```

**Ожидаемая производительность:** ~30-36 MH/s

**Потребление энергии:** ~90-110W

---

### Режим 35904 — Ethereum Brainwallet (SHA3-256)

#### Максимальная скорость

```bash
./hashcat -m 35904 -a 0 ethereum_addresses.txt wordlist.txt \
  --backend-devices 1 \
  -O \
  -w 4 \
  -n 192 \
  --kernel-accel 48 \
  --kernel-loops 256 \
  --kernel-threads 128
```

**Ожидаемая производительность:** ~28-34 MH/s

**Потребление энергии:** ~110-130W

#### Стабильный режим

```bash
./hashcat -m 35904 -a 0 ethereum_addresses.txt wordlist.txt \
  --backend-devices 1 \
  -O \
  -w 3 \
  -n 128 \
  --kernel-accel 32 \
  --kernel-loops 128 \
  --kernel-threads 64 \
  --hwmon-temp-abort 80
```

**Ожидаемая производительность:** ~24-30 MH/s

**Потребление энергии:** ~90-110W

---

### Рекомендации по охлаждению и энергопотреблению (RTX 3050)

#### Охлаждение

1. **Система охлаждения**
   - Большинство RTX 3050 имеют двухвентиляторное охлаждение (dual-fan)
   - Обеспечить хороший воздушный поток в корпусе
   - Очистить пыль с радиаторов каждые 2-3 месяца

2. **Настройка вентиляторов**
   ```bash
   # Пример с использованием nvidia-settings (Linux)
   nvidia-settings -a "[gpu:0]/GPUFanControlState=1"
   nvidia-settings -a "[fan:0]/GPUTargetFanSpeed=70"
   ```

3. **Целевые температуры**
   - **Максимальный режим:** 65-75°C
   - **Стабильный режим:** 55-65°C
   - **Критическая температура:** 80°C (авто-остановка)

4. **Мониторинг**
   ```bash
   # Постоянный мониторинг температуры и утилизации
   watch -n 5 'nvidia-smi --query-gpu=temperature.gpu,utilization.gpu,power.draw --format=csv'
   ```

#### Энергопотребление

1. **Блок питания**
   - Минимальная мощность: **400W** (для системы с RTX 3050)
   - Рекомендуется: **500-550W** (80+ Bronze или лучше)

2. **Power Limit (ограничение мощности)**
   - RTX 3050 хорошо поддаётся снижению power limit без потери производительности
   ```bash
   # Установить лимит мощности на 85W (из 130W)
   nvidia-smi -i 0 -pl 85
   ```
   - С power limit 85W: ~85-95W потребление при ~90-95% производительности

3. **Стоимость электроэнергии**
   - При тарифе 5 руб/kWh:
     - Максимальный режим (120W): ~4.3 руб/сутки, ~130 руб/месяц
     - Стабильный режим (100W): ~3.6 руб/сутки, ~108 руб/месяц
     - С power limit (85W): ~3 руб/сутки, ~90 руб/месяц

---

## Общие рекомендации по оптимизации

### 1. Подбор параметров

Оптимальные параметры (`-n`, `--kernel-accel`, `--kernel-loops`, `--kernel-threads`) зависят от конкретного GPU и могут отличаться. Для поиска наилучших значений:

```bash
# Автоматический benchmark для определения оптимальных параметров
./hashcat -m 35900 -a 0 --benchmark
```

Или используйте режим tuning (автоматический подбор):
```bash
./hashcat -m 35900 -a 0 bitcoin_addresses.txt wordlist.txt --backend-devices 1 -O -w 4
```

Hashcat автоматически подберёт параметры, если вы не указали их явно.

### 2. Workload Profile (`-w`)

| Значение | Описание | Использование |
|----------|----------|---------------|
| `-w 1` | Low | Система остаётся отзывчивой, минимальная нагрузка на GPU |
| `-w 2` | Default | Баланс между производительностью и отзывчивостью |
| `-w 3` | High | Высокая производительность, система может подтормаживать |
| `-w 4` | Nightmare | Максимальная производительность, система может "зависнуть" |

**Рекомендации:**
- Для headless-серверов (без GUI): `-w 4`
- Для рабочих станций с GUI: `-w 2` или `-w 3`
- Для долгосрочной работы: `-w 3` (баланс производительность/стабильность)

### 3. Оптимизация OpenCL (для AMD)

1. **Установка правильного драйвера**
   - Для майнинговых ригов: **ROCm** или **Adrenalin Pro**
   - Для десктопов: **Adrenalin**

2. **Переменные окружения**
   ```bash
   export GPU_MAX_HEAP_SIZE=100
   export GPU_MAX_USE_SYNC_OBJECTS=1
   export GPU_SINGLE_ALLOC_PERCENT=100
   export GPU_MAX_ALLOC_PERCENT=100
   ```

3. **Компиляция OpenCL ядер**
   - При первом запуске hashcat компилирует ядра (может занять 1-5 минут)
   - Скомпилированные ядра кешируются в `~/.hashcat/kernels/`
   - Для переиспользования на других системах можно скопировать эту папку

### 4. Оптимизация CUDA (для NVIDIA)

1. **Установка последней версии драйвера**
   - Минимум: **525.x** для CUDA 12.x
   - Рекомендуется: **535.x+**

2. **CUDA Toolkit**
   - Не требуется для запуска hashcat
   - Может помочь при отладке

3. **Compute Mode**
   ```bash
   # Установить режим Exclusive Process (для серверов)
   nvidia-smi -i 0 -c 3
   ```

### 5. Работа с большими базами адресов

При работе с миллионами адресов:

1. **Достаточно RAM**
   - 30 млн адресов Ethereum (~42 байта на адрес): ~1.2 GB RAM
   - Рекомендуется иметь минимум 8 GB системной памяти

2. **SSD для быстрой загрузки**
   - Загрузка 30 млн адресов с HDD: ~30-60 секунд
   - Загрузка с SSD: ~5-10 секунд

3. **Формат файла**
   - Используйте файлы с переводами строк Unix (LF), а не Windows (CRLF)
   - Избегайте пустых строк в конце файла

### 6. Мониторинг и автоматизация

#### Скрипт мониторинга для AMD (7 GPU)

```bash
#!/bin/bash
# monitor_amd.sh

while true; do
  clear
  echo "=== AMD GPU Status ==="
  date
  echo ""
  
  for i in {0..6}; do
    temp=$(rocm-smi -d $i --showtemp | grep Temperature | awk '{print $3}')
    util=$(rocm-smi -d $i --showuse | grep GPU | awk '{print $3}')
    power=$(rocm-smi -d $i --showpower | grep Average | awk '{print $4}')
    
    echo "GPU $i: Temp=${temp}°C, Util=${util}%, Power=${power}W"
  done
  
  sleep 5
done
```

#### Скрипт мониторинга для NVIDIA

```bash
#!/bin/bash
# monitor_nvidia.sh

watch -n 5 'nvidia-smi --query-gpu=index,name,temperature.gpu,utilization.gpu,power.draw,memory.used --format=csv,noheader'
```

#### Автоматический перезапуск при сбое

```bash
#!/bin/bash
# auto_restart.sh

while true; do
  echo "Starting hashcat at $(date)"
  
  ./hashcat -m 35900 -a 0 bitcoin_addresses.txt wordlist.txt \
    --backend-devices 1,2,3,4,5,6,7 -O -w 3 \
    --hwmon-temp-abort 85 \
    --restore-timer 60
  
  exit_code=$?
  
  if [ $exit_code -eq 0 ]; then
    echo "Hashcat completed successfully"
    break
  else
    echo "Hashcat exited with code $exit_code, restarting in 10 seconds..."
    sleep 10
  fi
done
```

### 7. Типовые проблемы и решения

#### Проблема: GPU недоступна или не обнаруживается

**AMD:**
```bash
# Проверка видимости GPU
rocm-smi

# Переустановка драйвера (Ubuntu/Debian)
sudo apt purge amdgpu-install
sudo apt autoremove
# Установка ROCm
wget https://repo.radeon.com/amdgpu-install/latest/ubuntu/focal/amdgpu-install_*_all.deb
sudo dpkg -i amdgpu-install_*_all.deb
sudo amdgpu-install --opencl=rocr --usecase=workstation
```

**NVIDIA:**
```bash
# Проверка видимости GPU
nvidia-smi

# Переустановка драйвера (Ubuntu/Debian)
sudo apt purge nvidia-*
sudo apt autoremove
sudo ubuntu-drivers install
sudo reboot
```

#### Проблема: Низкая производительность

1. Проверьте температуру — троттлинг при >85°C
2. Проверьте загрузку GPU (`nvidia-smi` или `rocm-smi`) — должна быть близка к 100%
3. Попробуйте другие значения `-n`, `--kernel-accel`
4. Убедитесь, что используется флаг `-O` (оптимизация)
5. Для AMD: проверьте переменные окружения OpenCL

#### Проблема: GPU зависает или драйвер крашится

1. Снизьте workload profile: `-w 3` вместо `-w 4`
2. Уменьшите `--kernel-accel` и `-n`
3. Проверьте температуру и питание
4. Обновите драйвер GPU
5. Добавьте `--hwmon-temp-abort 80` для автоостановки

#### Проблема: Высокое энергопотребление

**AMD:**
```bash
# Undervolting через OverdriveN API
sudo su
echo "manual" > /sys/class/drm/card0/device/power_dpm_force_performance_level
echo "5 850" > /sys/class/drm/card0/device/pp_od_clk_voltage  # Core voltage
echo "2 900" > /sys/class/drm/card0/device/pp_od_clk_voltage  # Memory voltage
echo "c" > /sys/class/drm/card0/device/pp_od_clk_voltage      # Commit changes
```

**NVIDIA:**
```bash
# Ограничение мощности
nvidia-smi -i 0 -pl 85  # Лимит 85W для RTX 3050
```

### 8. Расширенные техники оптимизации

#### Использование нескольких словарей (pipe mode)

```bash
# Объединение нескольких словарей "на лету"
cat wordlist1.txt wordlist2.txt wordlist3.txt | ./hashcat -m 35900 bitcoin_addresses.txt
```

#### Distributed cracking (распределённая атака)

Для разделения нагрузки между несколькими ригами:

```bash
# Риг 1 (обрабатывает первую половину keyspace)
./hashcat -m 35900 -a 3 addresses.txt ?a?a?a?a?a?a --skip 0 --limit 50000000

# Риг 2 (обрабатывает вторую половину keyspace)
./hashcat -m 35900 -a 3 addresses.txt ?a?a?a?a?a?a --skip 50000000 --limit 50000000
```

#### Использование правил для увеличения словаря

```bash
# Применение нескольких файлов правил одновременно
./hashcat -m 35900 -a 0 addresses.txt wordlist.txt \
  -r rules/best64.rule \
  -r rules/toggles1.rule
```

### 9. Стратегии гибридных атак (-a 6 и -a 7) для корпоративных аудитов

Гибридные атаки комбинируют словари с масками, что делает их чрезвычайно эффективными для аудита реальных систем, где пользователи создают пароли по предсказуемым шаблонам.

#### Архитектура "Penetrator" — многоуровневая стратегия

**Уровень 1: Базовые паттерны (покрывает ~40% паролей)**

```bash
# 1.1. Слово + год (самый распространённый паттерн)
./hashcat -m 35900 -a 6 addresses.txt common_words.txt ?d?d?d?d

# 1.2. Слово + спецсимвол + цифры (compliance-паттерн)
./hashcat -m 35900 -a 6 addresses.txt corporate_dict.txt ?s?d?d

# 1.3. Слово + восклицательный знак (самый популярный спецсимвол)
./hashcat -m 35900 -a 6 addresses.txt wordlist.txt !

# 1.4. Слово + год + спецсимвол
./hashcat -m 35900 -a 6 addresses.txt wordlist.txt ?d?d?d?d?s
```

**Уровень 2: Расширенные паттерны (дополнительные ~20%)**

```bash
# 2.1. Год + слово (обратный порядок)
./hashcat -m 35900 -a 7 addresses.txt ?d?d?d?d wordlist.txt

# 2.2. Слово + месяц/день (01-31)
./hashcat -m 35900 -a 6 addresses.txt wordlist.txt -1 0123 ?1?d

# 2.3. Слово + короткий PIN (00-99)
./hashcat -m 35900 -a 6 addresses.txt wordlist.txt ?d?d

# 2.4. Префикс + слово + год
./hashcat -m 35900 -a 7 addresses.txt ?u wordlist_with_year_suffix.txt
```

**Уровень 3: Локализация и транслитерация (русскоязычные системы, ~15%)**

```bash
# 3.1. Транслитерированные слова + год
./hashcat -m 35900 -a 6 addresses.txt russian_translit_dict.txt ?d?d?d?d

# 3.2. Кириллица → латиница с l33t-заменами + цифры
./hashcat -m 35900 -a 0 addresses.txt russian_dict.txt -r rules/best64.rule

# 3.3. Смешанные паттерны (имя латиницей + год)
./hashcat -m 35900 -a 6 addresses.txt russian_names_translit.txt 19?d?d
```

**Уровень 4: Compliance-обход (пользователи обходят политику, ~10%)**

```bash
# 4.1. Слово + несколько спецсимволов подряд
./hashcat -m 35900 -a 6 addresses.txt wordlist.txt !!

# 4.2. Слово + increment (Password1, Password2, ...)
./hashcat -m 35900 -a 6 addresses.txt wordlist.txt ?d

# 4.3. Сложные маски (спецсимвол в середине + год)
./hashcat -m 35900 -a 0 addresses.txt wordlist.txt -r rules/dive.rule
```

#### Оптимизация производительности гибридных атак

**Важно:** Гибридные атаки (-a 6, -a 7) используют существующие ядра и имеют производительность, сопоставимую с -a 0 (словарь) или -a 3 (маска), в зависимости от длины маски.

**Рекомендации по параметрам для 7x RX 580:**

```bash
# Гибридная атака с короткой маской (1-4 символа)
./hashcat -m 35900 -a 6 addresses.txt large_wordlist.txt ?d?d?d?d \
  --backend-devices 1,2,3,4,5,6,7 \
  -O \
  -w 4 \
  -n 512 \
  --kernel-accel 128

# Гибридная атака с длинной маской (5-8 символов)
./hashcat -m 35900 -a 6 addresses.txt wordlist.txt ?d?d?d?d?d?d?d?d \
  --backend-devices 1,2,3,4,5,6,7 \
  -O \
  -w 3 \
  -n 256 \
  --kernel-accel 64  # Снижаем нагрузку из-за большого keyspace
```

**Рекомендации для GeForce RTX 3050:**

```bash
# Короткая маска
./hashcat -m 35900 -a 6 addresses.txt wordlist.txt ?d?d?d?d \
  -O \
  -w 3 \
  -n 256 \
  --kernel-accel 64

# Длинная маска
./hashcat -m 35900 -a 6 addresses.txt wordlist.txt ?a?a?a?a?a \
  -O \
  -w 2 \
  -n 128 \
  --kernel-accel 32
```

#### Практический пример: полный аудит b2b-системы

```bash
#!/bin/bash
# Скрипт поэтапного аудита корпоративной системы

HASH_FILE="bitcoin_addresses.txt"
DICT="corporate_wordlist.txt"
MODE=35900

# Этап 1: Базовый словарь (быстрая проверка)
echo "[1/7] Straight dictionary attack..."
./hashcat -m $MODE -a 0 $HASH_FILE $DICT --outfile found.txt --outfile-format 2

# Этап 2: Словарь + правила (compliance паттерны)
echo "[2/7] Dictionary + superrules..."
./hashcat -m $MODE -a 0 $HASH_FILE $DICT -r rules/superrules.rule --outfile found.txt --outfile-format 2

# Этап 3: Гибрид — слово + год (2015-2026)
echo "[3/7] Hybrid word + year..."
./hashcat -m $MODE -a 6 $HASH_FILE $DICT -1 12 ?d?d?1?d --outfile found.txt --outfile-format 2

# Этап 4: Гибрид — слово + спецсимвол + цифры
echo "[4/7] Hybrid word + special + digits..."
./hashcat -m $MODE -a 6 $HASH_FILE $DICT ?s?d?d --outfile found.txt --outfile-format 2

# Этап 5: Гибрид — год + слово
echo "[5/7] Hybrid year + word..."
./hashcat -m $MODE -a 7 $HASH_FILE ?d?d?d?d $DICT --outfile found.txt --outfile-format 2

# Этап 6: Комбинатор (два словаря)
echo "[6/7] Combinator attack..."
./hashcat -m $MODE -a 1 $HASH_FILE $DICT short_words.txt --outfile found.txt --outfile-format 2

# Этап 7: Брутфорс коротких паролей (если время позволяет)
echo "[7/7] Brute-force 6-char lowercase..."
./hashcat -m $MODE -a 3 $HASH_FILE ?l?l?l?l?l?l --outfile found.txt --outfile-format 2

echo "Audit complete. Check found.txt for results."
```

#### Когда использовать гибридные атаки

**✅ Используйте -a 6/7 когда:**
- Известны шаблоны паролей организации (аудит показал "слово+год")
- Система имеет политику сложности пароля (заставляет добавлять цифры/спецсимволы)
- Словарь качественный, но недостаточно полный
- Комбинаторная атака (-a 1) слишком медленная из-за больших словарей

**❌ НЕ используйте -a 6/7 когда:**
- Нет информации о паттернах (лучше начать с -a 0 + правила)
- Словарь уже содержит варианты с суффиксами
- Маска слишком длинная (>6 символов) — переходите к -a 3 с инкрементом

#### Ожидаемая производительность гибридных атак

**Режим 35900 (Bitcoin SHA-256):**

| Атака | Словарь | Маска | Комбинаций | Время (7x RX 580 @ 150 MH/s) |
|-------|---------|-------|------------|------------------------------|
| -a 6  | 100K слов | ?d?d?d?d | 1 млрд | ~1.8 часа |
| -a 6  | 1M слов | ?d?d?d?d | 10 млрд | ~18 часов |
| -a 6  | 100K слов | ?s?d?d | 3.7 млрд | ~7 часов |
| -a 7  | ?d?d?d?d | 100K слов | 1 млрд | ~1.8 часа |

**Режим 35903 (Ethereum SHA-256):**

Производительность аналогична режиму 35900 (тот же алгоритм хеширования, разная деривация адреса).

**Режим 35902 (Ethereum Keccak-256):**

Производительность может быть на 10-15% выше из-за особенностей Keccak-256.

---

## Практический аудит: Batch Address и Privkey List

### Описание сценария

Модуль 35910 (Ethereum Address Lookup) оптимизирован для массовой проверки списков адресов против сгенерированных ключей. Эта секция описывает практические аспекты работы с большими объемами данных на GPU.

### Архитектура GPU Batch Lookup

**Принцип работы:**

1. **Загрузка адресов в Bloom Filter**
   - При старте hashcat загружает все целевые адреса из файла
   - Строит bloom filter в оперативной памяти CPU
   - Передает bitset фильтра в GPU global memory

2. **GPU-генерация и сравнение**
   - Каждый GPU-поток генерирует кандидат (фраза → ключ → адрес)
   - Вычисленный адрес проверяется в bloom filter (на GPU)
   - При совпадении — финальная проверка на CPU

3. **False Positive обработка**
   - Bloom filter дает ~1% false positives
   - Каждый "hit" перепроверяется точным сравнением на CPU
   - Только реальные совпадения выводятся в результат

### Ограничения VRAM и стратегии работы

#### Расчет потребления памяти GPU

**Bloom Filter:**
- 10 bits per address (оптимальное для 1% FP rate)
- Memory = (addresses × 10) / 8 bytes

| Addresses | Bloom Filter | + Kernels | Total VRAM | Recommended GPU |
|-----------|--------------|-----------|------------|-----------------|
| 100,000 | 125 KB | ~500 MB | ~600 MB | Any GPU (2GB+) |
| 1,000,000 | 1.2 MB | ~500 MB | ~600 MB | RTX 3050 6GB |
| 10,000,000 | 12 MB | ~500 MB | ~600 MB | RTX 3050 6GB |
| 100,000,000 | 120 MB | ~500 MB | ~700 MB | RTX 3060 12GB |
| 500,000,000 | 600 MB | ~500 MB | ~1.2 GB | RTX 3090 24GB |
| 1,000,000,000 | 1.2 GB | ~500 MB | ~2 GB | RTX 3090 24GB |
| 5,000,000,000 | 6 GB | ~500 MB | ~7 GB | RTX 3090 24GB |

**Примечание:** "Kernels" — это память для рабочих буферов GPU (зависит от `-w`, `--kernel-accel`, количества потоков). Указаны типичные значения для `-w 3`.

#### Batched Processing для больших списков

Если список адресов превышает доступную VRAM, используйте пакетную обработку:

**Метод 1: Разделение файла адресов**

```bash
# Разбить файл на пакеты по 10M адресов
split -l 10000000 huge_eth_addresses.txt batch_

# Запустить на каждом пакете
for batch in batch_*; do
  echo "Processing $batch..."
  ./hashcat -m 35910 "$batch" wordlist.txt -o found.txt --outfile-format 2 --quiet
done

# Проверить найденные ключи
cat found.txt | sort -u > found_unique.txt
```

**Метод 2: Использование сессий с несколькими GPU**

```bash
# GPU 1 обрабатывает первую половину адресов
./hashcat -m 35910 addresses_part1.txt wordlist.txt --backend-devices 1 --session gpu1 &

# GPU 2 обрабатывает вторую половину
./hashcat -m 35910 addresses_part2.txt wordlist.txt --backend-devices 2 --session gpu2 &

# Ожидание завершения обоих
wait
```

**Метод 3: False Positive rate tuning**

Если нужно уместить больше адресов в фиксированную память:

```bash
# Увеличить FP rate до ~5% (меньше бит на адрес)
# Это позволяет загрузить в 2х больше адресов, но CPU будет больше перепроверять
# (Эта функция требует модификации кода bloom filter, пример концептуальный)
```

### Сравнение хешей на GPU: архитектурные особенности

#### AMD vs NVIDIA для Crypto Workloads

**AMD (OpenCL):**
- ✅ Хорошая производительность на SHA-256 и Keccak-256
- ✅ Больше stream processors (CU × 64 = SP count)
- ✅ Дешевле за MH/s в среднем
- ⚠️ Может быть сложнее настроить драйверы (ROCm)
- ⚠️ Поддержка OpenCL 2.0 (но не все фичи)

**NVIDIA (CUDA/OpenCL):**
- ✅ Отличная поддержка драйверов
- ✅ CUDA дает больше контроля (но hashcat использует OpenCL)
- ✅ Лучше для secp256k1 (elliptic curve math)
- ⚠️ Дороже за MH/s
- ⚠️ Меньше VRAM в бюджетных моделях

**Рекомендации:**
- Для домашних rig: AMD RX 580/6600/6900 (лучшая цена/производительность)
- Для профессионального использования: NVIDIA RTX 3090/4090 (стабильность, память)
- Для разработки и отладки: NVIDIA (лучшие инструменты профилирования)

#### Особенности secp256k1 на GPU

Эллиптическая кривая secp256k1 (используется в Bitcoin и Ethereum) требует:
- **256-bit bignum арифметику** (сложение, умножение, модулярная редукция)
- **Point multiplication** (скалярное умножение точки на кривой)
- **Conditional code paths** (могут вызывать warp divergence на GPU)

**Оптимизации в hashcat:**
- Precomputed base point (G) для ускорения
- Windowed NAF method для скалярного умножения
- Inline assembly для критических операций (NVIDIA PTX)
- Минимизация divergence через predication

### Реальные схемы доверительной проверки адресов/фильтров

#### Сценарий 1: Аудит корпоративного brainwallet хранилища

**Задача:** Проверить, не использовались ли слабые парольные фразы для генерации кошельков в компании.

**Шаги:**
1. Получить список всех корпоративных ETH/BTC адресов (с согласия)
2. Подготовить словарь из:
   - Названий продуктов компании
   - Имен сотрудников (публичных)
   - Общих парольных паттернов
   - Словаря leaked паролей (Have I Been Pwned)
3. Запустить атаку по словарю + правила
4. Если найдены совпадения — уведомить владельца о необходимости смены ключей

**Команда:**
```bash
./hashcat -m 35910 corporate_eth_addresses.txt \
  -a 0 combined_wordlist.txt \
  -r rules/best64.rule \
  -r rules/d3ad0ne.rule \
  -o audit_results.txt \
  --outfile-format 2 \
  -w 3
```

#### Сценарий 2: Восстановление частично известного ключа

**Задача:** Владелец кошелька помнит большую часть парольной фразы, но забыл несколько символов.

**Пример:** Фраза вида `mySecretPass????` (4 последних символа неизвестны)

**Шаги:**
1. Определить возможные символы (только цифры? буквы? спецсимволы?)
2. Создать маску на основе известной части
3. Запустить mask brute-force

**Команды:**

```bash
# Случай 1: Последние 4 символа — цифры
./hashcat -m 35910 my_eth_address.txt -a 3 'mySecretPass?d?d?d?d'

# Случай 2: Последние 4 символа — буквы или цифры
./hashcat -m 35910 my_eth_address.txt -a 3 -1 ?l?d 'mySecretPass?1?1?1?1'

# Случай 3: Известны первые 10 и последние 2, середина (6 символов) неизвестна
./hashcat -m 35910 my_eth_address.txt -a 3 'mySecretPa?l?l?l?l?l?l42'

# Случай 4: Инкремент — известно начало, неизвестна длина окончания (4-8 символов)
./hashcat -m 35910 my_eth_address.txt -a 3 'mySecretPass?a?a?a?a?a?a?a?a' \
  --increment --increment-min 4 --increment-max 8
```

**Оценка времени:**
```python
# Пример расчета для ?d?d?d?d (4 цифры)
combinations = 10^4 = 10,000
speed = 150 MH/s = 150,000,000 hashes/sec
time = 10,000 / 150,000,000 = 0.000067 sec (~мгновенно)

# Пример для ?l?l?l?l (4 строчные буквы)
combinations = 26^4 = 456,976
time = 456,976 / 150,000,000 ≈ 0.003 sec (~мгновенно)

# Пример для ?a?a?a?a (4 printable ASCII)
combinations = 95^4 = 81,450,625
time = 81,450,625 / 150,000,000 ≈ 0.5 sec

# Пример для ?a?a?a?a?a?a (6 printable ASCII) — ТРУДНО
combinations = 95^6 = 735,091,890,625
time = 735,091,890,625 / 150,000,000 ≈ 4,900 sec ≈ 1.4 часа

# Пример для ?a?a?a?a?a?a?a?a (8 printable ASCII) — ОЧЕНЬ ТРУДНО
combinations = 95^8 = 6,634,204,312,890,625
time = 6,634,204,312,890,625 / 150,000,000 ≈ 15 дней
```

**Практическая рекомендация:**
- До 4-5 неизвестных символов (?a) — реалистично на одном GPU
- 6-7 неизвестных — потребуется несколько дней на мощном GPU
- 8+ неизвестных — нужен кластер GPU или больше информации о паттерне

#### Сценарий 3: Batch-проверка "leaked" базы адресов

**Задача:** Проверить, есть ли в публичной базе адресов (например, из блокчейн-эксплореров) адреса, уязвимые к атаке brainwallet.

**⚠️ ВАЖНО:** Это должно делаться ТОЛЬКО в исследовательских целях для публикации уязвимостей или уведомления владельцев. Использование найденных ключей для кражи средств — НЕЗАКОННО.

**Шаги:**
1. Скачать список активных адресов с ненулевым балансом (публичные данные)
2. Отфильтровать адреса с балансом выше порога (исключить пыль)
3. Запустить проверку против словаря слабых паролей
4. Если найдены совпадения — опубликовать анонимный отчет (без приватных ключей)

**Команда:**
```bash
# Фильтрация адресов (пример, требуется скрипт)
python3 filter_addresses_with_balance.py blockchain_snapshot.csv > addresses_with_balance.txt

# Batch-проверка
./hashcat -m 35910 addresses_with_balance.txt \
  -a 0 weak_passwords_10M.txt \
  -w 3 -O \
  -o potential_vulnerable.txt \
  --outfile-format 2

# КРИТИЧЕСКИ ВАЖНО: НЕ публиковать найденные приватные ключи!
# Публиковать только статистику и общий отчет об уязвимостях
```

**Этический подход:**
1. Не использовать найденные ключи
2. Опубликовать отчет с анонимизированными данными
3. Уведомить сообщество о рисках brainwallet
4. Помочь владельцам переместить средства (если возможно связаться)

### Рекомендации по использованию Mask Brute для восстановления части ключа

#### Стратегия 1: От простого к сложному

```bash
# Шаг 1: Проверить только цифры (быстро)
./hashcat -m 35910 addr.txt -a 3 'known_part_?d?d?d?d'

# Шаг 2: Если не найдено — добавить строчные буквы
./hashcat -m 35910 addr.txt -a 3 -1 ?l?d 'known_part_?1?1?1?1'

# Шаг 3: Добавить заглавные буквы
./hashcat -m 35910 addr.txt -a 3 -1 ?l?u?d 'known_part_?1?1?1?1'

# Шаг 4: Полный printable ASCII (если всё еще не найдено)
./hashcat -m 35910 addr.txt -a 3 'known_part_?a?a?a?a'
```

#### Стратегия 2: Позиционный анализ

Если известны ограничения по позициям:

```bash
# Первый символ — заглавная, остальные — строчные/цифры
./hashcat -m 35910 addr.txt -a 3 -1 ?l?d 'known?u?1?1?1'

# Последний символ — спецсимвол (частое требование политик паролей)
./hashcat -m 35910 addr.txt -a 3 'known?l?l?l?s'

# Известен паттерн: слово + год (20XX)
./hashcat -m 35910 addr.txt -a 3 'known20?d?d'
```

#### Стратегия 3: Использование информации о пользователе

```bash
# Пример: Известно, что пользователь использовал дату рождения DDMMYY
./hashcat -m 35910 addr.txt -a 3 'username?d?d?d?d?d?d'

# Известно имя + любимое число (2-3 цифры)
./hashcat -m 35910 addr.txt -a 3 'john?d?d?d' --increment --increment-min 2 --increment-max 3
```

### Таблица скоростей и потребления памяти на разных устройствах

#### Производительность (Hash Rate)

| Устройство | Mode 35900 (BTC SHA-256) | Mode 35902 (ETH Keccak) | Mode 35910 (ETH Lookup) | TDP | Цена (USD, примерно) |
|------------|--------------------------|-------------------------|-------------------------|-----|----------------------|
| **Budget / Entry** |
| NVIDIA RTX 3050 6GB | 80-120 MH/s | 90-140 MH/s | 100-150 MH/s | 130W | $250 |
| AMD RX 6600 8GB | 90-130 MH/s | 100-150 MH/s | 110-160 MH/s | 132W | $270 |
| NVIDIA GTX 1660 Ti 6GB | 70-100 MH/s | 80-120 MH/s | 90-130 MH/s | 120W | $280 (used) |
| **Mid-range** |
| NVIDIA RTX 3060 12GB | 150-200 MH/s | 170-230 MH/s | 180-250 MH/s | 170W | $350 |
| AMD RX 6700 XT 12GB | 170-230 MH/s | 190-260 MH/s | 200-280 MH/s | 230W | $380 |
| NVIDIA RTX 3070 8GB | 180-240 MH/s | 200-270 MH/s | 210-290 MH/s | 220W | $500 |
| AMD RX 6800 XT 16GB | 220-300 MH/s | 250-340 MH/s | 260-360 MH/s | 300W | $600 |
| **High-end** |
| NVIDIA RTX 3090 24GB | 300-500 MH/s | 350-600 MH/s | 400-650 MH/s | 350W | $1,500 |
| AMD RX 6900 XT 16GB | 250-400 MH/s | 280-450 MH/s | 300-500 MH/s | 300W | $1,000 |
| NVIDIA RTX 4070 Ti 12GB | 280-450 MH/s | 320-510 MH/s | 350-550 MH/s | 285W | $800 |
| NVIDIA RTX 4080 16GB | 400-600 MH/s | 450-680 MH/s | 500-750 MH/s | 320W | $1,200 |
| NVIDIA RTX 4090 24GB | 500-800 MH/s | 600-950 MH/s | 650-1050 MH/s | 450W | $1,600 |
| **Workstation / Pro** |
| NVIDIA A100 40GB | 400-700 MH/s | 450-800 MH/s | 500-850 MH/s | 400W | $10,000+ |
| NVIDIA H100 80GB | 600-1000 MH/s | 700-1200 MH/s | 750-1300 MH/s | 700W | $30,000+ |

**Примечания:**
- Hash rate указан для режима `-w 3` (высокая нагрузка, система отзывчива)
- Для `-w 4` (nightmare) производительность может быть на 5-10% выше, но система "замерзнет"
- Реальные значения зависят от охлаждения, разгона, версии драйвера, длины парольной фразы
- Workstation карты (A100/H100) редко используются для этих задач из-за стоимости

#### Максимальная загрузка адресов в bloom filter (VRAM limit)

| Устройство | VRAM | Bloom Filter Only | + Kernels (realistically) | Max Addresses |
|------------|------|-------------------|---------------------------|---------------|
| NVIDIA RTX 3050 6GB | 6 GB | 5.5 GB | 5 GB | ~4 млрд адресов |
| NVIDIA RTX 3060 12GB | 12 GB | 11.5 GB | 11 GB | ~8.8 млрд адресов |
| NVIDIA RTX 3090 24GB | 24 GB | 23.5 GB | 23 GB | ~18.4 млрд адресов |
| AMD RX 6900 XT 16GB | 16 GB | 15.5 GB | 15 GB | ~12 млрд адресов |
| NVIDIA RTX 4090 24GB | 24 GB | 23.5 GB | 23 GB | ~18.4 млрд адресов |
| NVIDIA A100 40GB | 40 GB | 39.5 GB | 39 GB | ~31.2 млрд адресов |

**Расчет:** `Max Addresses = (VRAM in bytes × 8) / 10 bits per address`

**Пример для RTX 3090:**
- 23 GB = 23 × 1024^3 bytes = 24,696,061,952 bytes
- In bits = 24,696,061,952 × 8 = 197,568,495,616 bits
- Addresses = 197,568,495,616 / 10 ≈ 19.7 billion addresses

**Практический совет:** Bloom filter обычно занимает < 1GB даже для 500M адресов, поэтому ограничение VRAM редко является проблемой для реальных сценариев.

#### Производительность на доллар (MH/s per $)

| Устройство | Hash Rate (avg) | Цена | MH/s / $ | Энергоэффективность (MH/s / Watt) |
|------------|-----------------|------|----------|-------------------------------------|
| AMD RX 6600 8GB | 115 MH/s | $270 | **0.43** | 0.87 |
| NVIDIA RTX 3050 6GB | 110 MH/s | $250 | **0.44** | 0.85 |
| AMD RX 6700 XT 12GB | 210 MH/s | $380 | **0.55** | 0.91 |
| NVIDIA RTX 3060 12GB | 200 MH/s | $350 | **0.57** | 1.18 |
| AMD RX 6800 XT 16GB | 280 MH/s | $600 | **0.47** | 0.93 |
| NVIDIA RTX 3090 24GB | 500 MH/s | $1,500 | **0.33** | 1.43 |
| NVIDIA RTX 4090 24GB | 800 MH/s | $1,600 | **0.50** | 1.78 |

**Рекомендации по соотношению цена/производительность:**
- 🥇 **Лучший бюджет:** AMD RX 6600 / NVIDIA RTX 3050
- 🥈 **Лучший mid-range:** AMD RX 6700 XT / NVIDIA RTX 3060
- 🥉 **Лучший high-end:** NVIDIA RTX 4090 (+ большая VRAM для будущих задач)

#### Пример расчета окупаемости для аудиторской компании

**Сценарий:** Аудиторская фирма проводит ~10 аудитов в год, каждый требует ~500 GPU-часов.

**Вариант 1: Аренда облачных GPU**
- AWS g5.xlarge (NVIDIA A10G 24GB): $1.00/час
- Стоимость на аудит: 500 часов × $1.00 = $500
- Годовая стоимость: 10 × $500 = **$5,000/год**

**Вариант 2: Покупка собственного оборудования**
- 2x NVIDIA RTX 4090 24GB: $3,200
- Электричество (500 часов × 2 GPU × 450W × $0.12/kWh): ~$54/audit
- Годовая стоимость: $3,200 (первый год) + 10 × $54 = **$3,740 первый год**, **$540/год далее**

**Вывод:** Покупка окупается за <1 год для регулярных аудитов.

---

## Заключение

Данное руководство предоставляет отправные точки для оптимизации hashcat на различном оборудовании. Реальные значения производительности могут варьироваться в зависимости от:

- Качества охлаждения
- Качества блока питания
- Версии драйвера
- Версии hashcat
- Конкретной партии GPU (silicon lottery)

**Рекомендуется:**
1. Начать со "стабильных" конфигураций
2. Постепенно увеличивать параметры, наблюдая за температурой и стабильностью
3. Запустить тестовую сессию на 12-24 часа перед долгосрочной работой
4. Регулярно мониторить состояние оборудования
5. Использовать автоматический перезапуск при сбоях

**Важно:** Данные о производительности являются приблизительными и основаны на типичных значениях для указанного оборудования. Для точных измерений используйте режим benchmark:

```bash
./hashcat -m 35900 --benchmark
```

Happy cracking!
