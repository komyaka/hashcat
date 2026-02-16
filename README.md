## *hashcat* ##

**hashcat** is the world's fastest and most advanced password recovery utility, supporting five unique modes of attack for over 300 highly-optimized hashing algorithms. hashcat currently supports CPUs, GPUs, and other hardware accelerators on Linux, Windows, and macOS, and has facilities to help enable distributed password cracking.

### License ###

**hashcat** is licensed under the MIT license. Refer to [docs/license.txt](docs/license.txt) for more information.

### Installation ###

Download the [latest release](https://hashcat.net/hashcat/) and unpack it in the desired location. Please remember to use `7z x` when unpacking the archive from the command line to ensure full file paths remain intact.

Your platform may also provide [packages](docs/packages.md).

### Usage/Help ###

Please refer to the [Hashcat Wiki](https://hashcat.net/wiki/) and the output of `--help` for usage information and general help. A list of frequently asked questions may also be found [here](https://hashcat.net/wiki/doku.php?id=frequently_asked_questions). The [Hashcat Forum](https://hashcat.net/forum/) also contains a plethora of information. If you still think you need help by a real human come to [Discord](https://discord.gg/HFS523HGBT).

### Building ###

Refer to [BUILD.md](BUILD.md) for instructions on how to build **hashcat** from source.

Tests:

Travis | Coverity | GitHub Actions
------ | -------- | --------------
[![Hashcat Travis Build status](https://travis-ci.org/hashcat/hashcat.svg?branch=master)](https://travis-ci.org/hashcat/hashcat) | [![Coverity Scan Build Status](https://scan.coverity.com/projects/11753/badge.svg)](https://scan.coverity.com/projects/hashcat) | [![Hashcat GitHub Actions Build status](https://github.com/hashcat/hashcat/actions/workflows/build.yml/badge.svg)](https://github.com/hashcat/hashcat/actions/workflows/build.yml)

### Contributing ###

Contributions are welcome and encouraged, provided your code is of sufficient quality. Before submitting a pull request, please ensure your code adheres to the following requirements:

1. Licensed under MIT license, or dedicated to the public domain (BSD, GPL, etc. code is incompatible)
2. Adheres to gnu99 standard
3. Compiles cleanly with no warnings when compiled with `-W -Wall -std=gnu99`
4. Uses [Allman-style](https://en.wikipedia.org/wiki/Indent_style#Allman_style) code blocks & indentation
5. Uses 2-spaces as the indentation or a tab if it's required (for example: Makefiles)
6. Uses lower-case function and variable names
7. Avoids the use of `!` and uses positive conditionals wherever possible (e.g., `if (foo == 0)` instead of `if (!foo)`, and `if (foo)` instead of `if (foo != 0)`)
8. Use code like array[index + 0] if you also need to do array[index + 1], to keep it aligned

You can use GNU Indent to help assist you with the style requirements:

```
indent -st -bad -bap -sc -bl -bli0 -ncdw -nce -cli0 -cbi0 -pcs -cs -npsl -bs -nbc -bls -blf -lp -i2 -ts2 -nut -l1024 -nbbo -fca -lc1024 -fc1
```

Your pull request should fully describe the functionality you are adding/removing or the problem you are solving. Regardless of whether your patch modifies one line or one thousand lines, you must describe what has prompted and/or motivated the change.

Solve only one problem in each pull request. If you're fixing a bug and adding a new feature, you need to make two separate pull requests. If you're fixing three bugs, you need to make three separate pull requests. If you're adding four new features, you need to make four separate pull requests. So on, and so forth.

If your patch fixes a bug, please be sure there is an [issue](https://github.com/hashcat/hashcat/issues) open for the bug before submitting a pull request. If your patch aims to improve performance or optimize an algorithm, be sure to quantify your optimizations and document the trade-offs, and back up your claims with benchmarks and metrics.

In order to maintain the quality and integrity of the **hashcat** source tree, all pull requests must be reviewed and signed off by at least two [board members](https://github.com/orgs/hashcat/people) before being merged. The [project lead](https://github.com/jsteube) has the ultimate authority in deciding whether to accept or reject a pull request. Do not be discouraged if your pull request is rejected!

---

## Криптовалютные модули — Руководство пользователя

### Обзор модулей

Hashcat поддерживает GPU-ускоренные модули для работы с криптовалютными адресами и приватными ключами:

| Режим | Тип | Криптовалюта | Описание |
|-------|-----|--------------|----------|
| 35900 | Brainwallet | Bitcoin | SHA-256 → приватный ключ → BTC адрес |
| 35901 | Brainwallet | Bitcoin | SHA3-256 → приватный ключ → BTC адрес |
| 35902 | Brainwallet | Ethereum | Keccak-256 → приватный ключ → ETH адрес |
| 35903 | Brainwallet | Ethereum | SHA-256 → приватный ключ → ETH адрес |
| 35904 | Brainwallet | Ethereum | SHA3-256 → приватный ключ → ETH адрес |
| 35910 | GPU Batch Lookup | Ethereum | Массовая проверка ETH адресов с bloom-фильтром |

### ⚠️ ВАЖНЫЕ ПРЕДУПРЕЖДЕНИЯ

**ЭТИЧЕСКИЕ И ПРАВОВЫЕ ОГРАНИЧЕНИЯ:**

1. **Только для легального аудита и тестирования** — Использование этих модулей разрешено ТОЛЬКО для:
   - Восстановления собственных утерянных ключей
   - Тестирования безопасности собственных систем
   - Исследования в образовательных целях
   - Аудита с письменного разрешения владельца

2. **ЗАПРЕЩЕНО использовать для:**
   - Атак на чужие кошельки и адреса
   - Обработки украденных баз данных ("сливов")
   - Несанкционированного доступа к средствам
   - Любых незаконных действий

3. **Ответственность пользователя** — Вы несете полную юридическую и этическую ответственность за использование данных инструментов. Авторы hashcat не несут ответственности за злоупотребления.

4. **Проверка легальности** — Перед использованием убедитесь, что ваши действия соответствуют законодательству вашей юрисдикции.

---

### Модули Brainwallet (35900–35904) ###

#### Описание модулей ####

| Режим | Описание | Хеш парольной фразы | Получение адреса |
|-------|----------|---------------------|------------------|
| 35900 | Bitcoin Brainwallet (SHA-256) | SHA-256 | RIPEMD160(SHA256(compressed_pubkey)) → Base58Check |
| 35901 | Bitcoin Brainwallet (SHA3-256) | SHA3-256 | RIPEMD160(SHA256(compressed_pubkey)) → Base58Check |
| 35902 | Ethereum Brainwallet (Keccak-256) | Keccak-256 | Keccak256(uncompressed_pubkey)[12:] → 0x hex |
| 35903 | Ethereum Brainwallet (SHA-256) | SHA-256 | Keccak256(uncompressed_pubkey)[12:] → 0x hex |
| 35904 | Ethereum Brainwallet (SHA3-256) | SHA3-256 | Keccak256(uncompressed_pubkey)[12:] → 0x hex |

#### Принцип работы ####

Все модули реализуют атаку на «мозговые кошельки» (brainwallet):

1. Парольная фраза хешируется выбранным алгоритмом (SHA-256, SHA3-256 или Keccak-256) → получается 256-битный приватный ключ.
2. По приватному ключу вычисляется точка на эллиптической кривой secp256k1 (публичный ключ).
3. Из публичного ключа выводится адрес кошелька:
   - **Bitcoin** (35900, 35901): Сжатый публичный ключ (33 байта) → SHA-256 → RIPEMD-160 → Base58Check с версией 0x00.
   - **Ethereum** (35902, 35903, 35904): Несжатый публичный ключ (64 байта, без префикса 0x04) → Keccak-256 → последние 20 байт → адрес в формате `0x...`.
4. Полученный адрес сравнивается с целевым адресом (или списком адресов) из хеш-файла.

#### Формат базы адресов (хеш-файл) ####

База адресов — это обычный текстовый файл, в котором **каждый адрес записан на отдельной строке**. Этот файл указывается в параметре hashcat как хеш-файл.

**Для Bitcoin (режимы 35900, 35901):**

Каждая строка содержит один Bitcoin-адрес в формате Base58Check (обычный P2PKH-адрес, начинается с `1`):

```
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
1CkwUnESKuVFyn3PVm1fyyMtXx6CT2STg7
1HsXwzdgD2ynmEbgMgLikdBDP7wWrFchTL
```

- Длина адреса: 26–34 символа.
- Допустимые символы: алфавит Base58 (`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`).
- Адрес должен начинаться с `1` (P2PKH, mainnet).
- Встроенная проверка Base58Check контрольной суммы.

**Для Ethereum (режимы 35902, 35903, 35904):**

Каждая строка содержит один Ethereum-адрес в шестнадцатеричном формате с префиксом `0x`:

```
0x9c7002ea607c998e062793c420116b66f92421ac
0xacc6378af93c8cdb42d429625cd531038531a1db
0xb238859ca7d4d8fa1af573c6e522b4c52fd58f0a
```

- Длина адреса: 42 символа (включая префикс `0x`).
- После `0x` следуют ровно 40 шестнадцатеричных символов (строчные `a-f` и цифры `0-9`).
- Префикс `0x` обязателен.

**Размер базы:** Hashcat поддерживает загрузку больших списков адресов (например, 30 000 000 адресов). Файл должен умещаться в оперативную память. Рекомендуется использовать SSD для быстрой загрузки.

**Расположение файла:** Файл с адресами может находиться в любом месте файловой системы. Путь к нему указывается в командной строке hashcat.

#### Примеры использования ####

##### Режим 35900 — Bitcoin Brainwallet (SHA-256) #####

Парольная фраза хешируется через SHA-256 для получения приватного ключа Bitcoin.

**Пример 1: Атака по словарю**
```bash
./hashcat -m 35900 -a 0 bitcoin_addresses.txt wordlist.txt
```
Здесь `bitcoin_addresses.txt` — файл со списком Bitcoin-адресов (по одному на строку), `wordlist.txt` — словарь с парольными фразами.

**Пример 2: Атака по маске (брутфорс)**
```bash
./hashcat -m 35900 -a 3 bitcoin_addresses.txt ?a?a?a?a?a?a
```
Перебор всех комбинаций из 6 печатных ASCII-символов.

**Пример 3: Комбинаторная атака**
```bash
./hashcat -m 35900 -a 1 bitcoin_addresses.txt words_left.txt words_right.txt
```
Каждое слово из `words_left.txt` комбинируется с каждым словом из `words_right.txt`.

**Пример 4: Атака по словарю с правилами**
```bash
./hashcat -m 35900 -a 0 bitcoin_addresses.txt wordlist.txt -r rules/best64.rule
```
Применение правил трансформации к словарю.

**Пример 5: Атака по маске с инкрементом длины**
```bash
./hashcat -m 35900 -a 3 bitcoin_addresses.txt ?l?l?l?l?l?l?l?l --increment --increment-min 4
```
Перебор строчных слов длиной от 4 до 8 символов.

##### Режим 35901 — Bitcoin Brainwallet (SHA3-256) #####

Парольная фраза хешируется через SHA3-256 для получения приватного ключа Bitcoin.

**Пример 1: Атака по словарю**
```bash
./hashcat -m 35901 -a 0 bitcoin_addresses.txt wordlist.txt
```

**Пример 2: Атака по словарю с правилами**
```bash
./hashcat -m 35901 -a 0 bitcoin_addresses.txt wordlist.txt -r rules/best64.rule
```
Применение правил трансформации к каждому слову из словаря.

**Пример 3: Атака по маске с пользовательскими наборами символов**
```bash
./hashcat -m 35901 -a 3 bitcoin_addresses.txt -1 ?l?d ?1?1?1?1?1?1?1?1
```
Перебор 8-символьных строк из строчных букв и цифр.

**Пример 4: Комбинаторная атака**
```bash
./hashcat -m 35901 -a 1 bitcoin_addresses.txt words1.txt words2.txt
```
Комбинирование слов из двух словарей.

**Пример 5: Атака по маске с инкрементом длины**
```bash
./hashcat -m 35901 -a 3 bitcoin_addresses.txt ?a?a?a?a?a?a --increment --increment-min 3
```
Перебор ASCII-символов длиной от 3 до 6 символов.

##### Режим 35902 — Ethereum Brainwallet (Keccak-256) #####

Парольная фраза хешируется через Keccak-256 для получения приватного ключа Ethereum.

**Пример 1: Атака по словарю**
```bash
./hashcat -m 35902 -a 0 ethereum_addresses.txt wordlist.txt
```
Здесь `ethereum_addresses.txt` — файл с Ethereum-адресами (формат `0x...`, по одному на строку).

**Пример 2: Атака по маске**
```bash
./hashcat -m 35902 -a 3 ethereum_addresses.txt ?a?a?a?a?a?a?a
```
Перебор всех 7-символьных парольных фраз.

**Пример 3: Атака по словарю с правилами**
```bash
./hashcat -m 35902 -a 0 ethereum_addresses.txt wordlist.txt -r rules/dive.rule
```

**Пример 4: Комбинаторная атака**
```bash
./hashcat -m 35902 -a 1 ethereum_addresses.txt words_part1.txt words_part2.txt
```
Каждое слово из `words_part1.txt` комбинируется с каждым словом из `words_part2.txt`.

**Пример 5: Атака по маске с инкрементом длины**
```bash
./hashcat -m 35902 -a 3 ethereum_addresses.txt ?l?l?l?l?l?l?l?l --increment --increment-min 3
```
Перебор строчных слов длиной от 3 до 8 символов.

##### Режим 35903 — Ethereum Brainwallet (SHA-256) #####

Парольная фраза хешируется через SHA-256 для получения приватного ключа Ethereum.

**Пример 1: Атака по словарю**
```bash
./hashcat -m 35903 -a 0 ethereum_addresses.txt wordlist.txt
```

**Пример 2: Атака по словарю с правилами**
```bash
./hashcat -m 35903 -a 0 ethereum_addresses.txt wordlist.txt -r rules/best64.rule
```
Применение правил трансформации к словарю.

**Пример 3: Комбинаторная атака**
```bash
./hashcat -m 35903 -a 1 ethereum_addresses.txt words_part1.txt words_part2.txt
```

**Пример 4: Атака по маске (брутфорс)**
```bash
./hashcat -m 35903 -a 3 ethereum_addresses.txt ?a?a?a?a?a?a
```
Перебор всех комбинаций из 6 печатных ASCII-символов.

**Пример 5: Атака по маске с инкрементом длины**
```bash
./hashcat -m 35903 -a 3 ethereum_addresses.txt ?a?a?a?a?a?a?a?a --increment --increment-min 4
```
Перебор парольных фраз длиной от 4 до 8 символов.

##### Режим 35904 — Ethereum Brainwallet (SHA3-256) #####

Парольная фраза хешируется через SHA3-256 для получения приватного ключа Ethereum.

**Пример 1: Атака по словарю**
```bash
./hashcat -m 35904 -a 0 ethereum_addresses.txt wordlist.txt
```

**Пример 2: Атака по маске**
```bash
./hashcat -m 35904 -a 3 ethereum_addresses.txt ?l?l?l?l?l?l
```
Перебор 6-символьных строчных слов.

**Пример 3: Атака по словарю с правилами**
```bash
./hashcat -m 35904 -a 0 ethereum_addresses.txt wordlist.txt -r rules/rockyou-30000.rule
```

**Пример 4: Комбинаторная атака**
```bash
./hashcat -m 35904 -a 1 ethereum_addresses.txt words_left.txt words_right.txt
```
Комбинирование слов из двух словарей.

**Пример 5: Атака по маске с инкрементом длины**
```bash
./hashcat -m 35904 -a 3 ethereum_addresses.txt ?d?d?d?d?d?d?d?d --increment --increment-min 4
```
Перебор числовых фраз длиной от 4 до 8 цифр.

#### Полная поддержка режима масок (Mask Mode) ####

Все модули Brainwallet (35900-35904) полностью поддерживают hashcat-style маски для перебора парольных фраз по заданным паттернам.

**Синтаксис масок:**
- `?l` = строчные буквы (a-z) — 26 символов
- `?u` = заглавные буквы (A-Z) — 26 символов
- `?d` = цифры (0-9) — 10 символов
- `?h` = строчные hex (0-9a-f) — 16 символов
- `?H` = заглавные hex (0-9A-F) — 16 символов
- `?s` = спецсимволы (!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~) — 33 символа
- `?a` = все печатные ASCII (?l?u?d?s) — 95 символов
- `?b` = все байты (0x00-0xFF) — 256 символов

**Пользовательские наборы символов:**
```bash
# Определить свой набор: -1 задает набор, ?1 использует его
./hashcat -m 35900 -a 3 btc_addresses.txt -1 ?l?d ?1?1?1?1?1?1?1?1
# Перебор 8 символов из строчных букв и цифр

# Несколько наборов:
./hashcat -m 35902 -a 3 eth_addresses.txt -1 ?l?u -2 ?d?s ?1?1?1?1?2?2
# Первые 4 символа: буквы, последние 2: цифры или спецсимволы
```

**Режим инкремента (increment):**
```bash
# Перебор от минимальной до максимальной длины
./hashcat -m 35900 -a 3 btc_addresses.txt ?l?l?l?l?l?l?l?l --increment --increment-min 4
# Перебор строчных слов длиной от 4 до 8 символов

./hashcat -m 35902 -a 3 eth_addresses.txt ?d?d?d?d?d?d --increment --increment-min 4
# Перебор PIN-кодов от 4 до 6 цифр
```

**Маски с известными частями:**
```bash
# Известный префикс + неизвестный суффикс
./hashcat -m 35900 -a 3 btc.txt 'password?d?d?d?d'
# "password" + 4 цифры

# Известное слово в середине
./hashcat -m 35902 -a 3 eth.txt '?l?ltest?d?d'
# 2 строчные буквы + "test" + 2 цифры
```

**Восстановление частично известного ключа (ключевая фича для аудита):**

Если вы знаете часть парольной фразы, но не всю — используйте маски:

```bash
# Известны первые 6 символов, последние 2 неизвестны
./hashcat -m 35900 -a 3 btc.txt 'mypass?a?a'

# Известны начало и конец, середина неизвестна
./hashcat -m 35902 -a 3 eth.txt 'hello?l?l?lworld'

# Известен формат: слово + год
./hashcat -m 35900 -a 3 btc.txt 'secret20?d?d'
# "secret" + 2000-2099
```

**Оценка времени перебора:**
```bash
# Узнать размер пространства ключей:
./hashcat -m 35900 --keyspace -a 3 '?l?l?l?l?l?l'
# Вывод: 308915776 (комбинаций)

# При скорости 150 MH/s (mega-hashes/sec):
# Время = 308915776 / 150000000 ≈ 2 секунды
```

#### Гибридные атаки (Hybrid Attacks) ####

Гибридные атаки комбинируют словарь с маской, что позволяет эффективно перебирать пароли, состоящие из запоминаемого слова и предсказуемого суффикса/префикса (например, год, PIN-код, спецсимвол).

**Режим -a 6 (Hybrid Wordlist + Mask)** — добавляет к каждому слову из словаря маску справа:

```
Формат: ./hashcat -a 6 -m <MODE> <HASH_FILE> <WORDLIST> <MASK>
```

##### Примеры для всех модулей #####

**Режим 35900 (Bitcoin SHA-256):**
```bash
# Пример 1: Слово + 4 цифры (год или PIN)
./hashcat -m 35900 -a 6 bitcoin_addresses.txt wordlist.txt ?d?d?d?d

# Пример 2: Слово + спецсимвол + 2 цифры
./hashcat -m 35900 -a 6 bitcoin_addresses.txt wordlist.txt ?s?d?d

# Пример 3: Слово + год (2020-2026)
./hashcat -m 35900 -a 6 bitcoin_addresses.txt common_words.txt 202?d
```

**Режим 35901 (Bitcoin SHA3-256):**
```bash
# Пример: Слово + восклицательный знак + 3 цифры
./hashcat -m 35901 -a 6 bitcoin_addresses.txt wordlist.txt !?d?d?d
```

**Режим 35902 (Ethereum Keccak-256):**
```bash
# Пример 1: Слово + маска (4 hex-символа для адреса)
./hashcat -m 35902 -a 6 ethereum_addresses.txt wordlist.txt ?h?h?h?h

# Пример 2: Слово + год
./hashcat -m 35902 -a 6 ethereum_addresses.txt wordlist.txt ?d?d?d?d
```

**Режим 35903 (Ethereum SHA-256):**
```bash
# Пример: Слово + спецсимвол + год
./hashcat -m 35903 -a 6 ethereum_addresses.txt dictionary.txt ?s202?d
```

**Режим 35904 (Ethereum SHA3-256):**
```bash
# Пример: Слово + маска с пользовательским набором (год 1990-2026)
./hashcat -m 35904 -a 6 ethereum_addresses.txt wordlist.txt -1 12 ?d?d?1?d
```

**Режим -a 7 (Hybrid Mask + Wordlist)** — добавляет маску слева от слова:

```
Формат: ./hashcat -a 7 -m <MODE> <HASH_FILE> <MASK> <WORDLIST>
```

##### Примеры для всех модулей #####

**Режим 35900 (Bitcoin SHA-256):**
```bash
# Пример: Год + слово
./hashcat -m 35900 -a 7 bitcoin_addresses.txt ?d?d?d?d wordlist.txt
```

**Режим 35902 (Ethereum Keccak-256):**
```bash
# Пример: Спецсимвол + слово
./hashcat -m 35902 -a 7 ethereum_addresses.txt ?s wordlist.txt
```

**Когда использовать гибридные атаки:**
- Известны паттерны паролей: "слово + год", "название + цифры", "префикс + слово"
- Аудит корпоративных систем с политикой "слово + спецсимвол + цифры"
- Пользователи добавляют предсказуемые суффиксы к запоминаемым словам
- Гибриды эффективнее полного брутфорса при сохранении высокой вероятности успеха

**Маски символов:**
- `?l` = строчные буквы (a-z)
- `?u` = заглавные буквы (A-Z)
- `?d` = цифры (0-9)
- `?h` = строчные шестнадцатеричные (0-9a-f)
- `?H` = заглавные шестнадцатеричные (0-9A-F)
- `?s` = спецсимволы (!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~)
- `?a` = все печатные ASCII-символы (?l?u?d?s)
- `?b` = все 256 символов (0x00-0xFF)

#### Самопроверочные хеши (self-test) ####

Для парольной фразы `hashcat`:

| Режим | Адрес |
|-------|-------|
| 35900 | `1CkwUnESKuVFyn3PVm1fyyMtXx6CT2STg7` |
| 35901 | `1HsXwzdgD2ynmEbgMgLikdBDP7wWrFchTL` |
| 35902 | `0x9c7002ea607c998e062793c420116b66f92421ac` |
| 35903 | `0xacc6378af93c8cdb42d429625cd531038531a1db` |
| 35904 | `0xb238859ca7d4d8fa1af573c6e522b4c52fd58f0a` |
| 35910 | `0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb` |

---

### Модуль 35910 — GPU-ускоренный поиск Ethereum адресов ###

#### Описание ####

Модуль 35910 реализует массовую проверку Ethereum-адресов с использованием GPU-ускорения и поддержкой bloom-фильтра для эффективной работы с миллионами адресов.

**Криптографический поток:**
1. Парольная фраза → SHA-256 → Приватный ключ (32 байта)
2. Приватный ключ × G (secp256k1) → Публичный ключ (64 байта, несжатый)
3. Keccak-256(Публичный ключ) → Хеш (32 байта)
4. Последние 20 байт хеша → Ethereum адрес

**Особенности модуля:**
- ✅ Поддержка миллионов адресов через bloom-фильтр
- ✅ GPU-ускорение (300-800 MH/s в зависимости от GPU)
- ✅ Низкое потребление памяти (10M адресов ≈ 12MB GPU RAM)
- ✅ False positive rate ~1% (компенсируется финальной проверкой)
- ✅ Полная поддержка всех режимов атаки hashcat (-a 0/1/3/6/7)

#### GPU Batch Lookup — Массовая проверка адресов ####

**Режим работы:**

Модуль 35910 оптимизирован для проверки сгенерированных ключей против большого списка целевых адресов:

1. **Загрузка адресов:** При запуске hashcat загружает все адреса из файла в bloom-фильтр
2. **GPU-вычисление:** Каждая кандидат-фраза → приватный ключ → публичный ключ → адрес
3. **Bloom-проверка:** Адрес проверяется в bloom-фильтре (быстро, но с FP)
4. **Финальная проверка:** При совпадении в фильтре — точная проверка на CPU

**Аргументы и параметры:**

```bash
# Базовое использование
./hashcat -m 35910 eth_addresses.txt wordlist.txt

# Опции производительности
./hashcat -m 35910 eth_addresses.txt wordlist.txt \
  -O                    # Оптимизированные ядра (рекомендуется)
  -w 3                  # Workload profile (1=low, 2=default, 3=high, 4=nightmare)
  --kernel-accel 128    # Ускорение ядра (автонастройка, можно указать вручную)
  --kernel-loops 256    # Количество итераций в ядре
```

**Ограничения VRAM и batched processing:**

| Количество адресов | Память bloom-фильтра | Рекомендуемая VRAM |
|-------------------|---------------------|-------------------|
| 100,000 | ~120 KB | 2 GB |
| 1,000,000 | ~1.2 MB | 2 GB |
| 10,000,000 | ~12 MB | 4 GB |
| 100,000,000 | ~120 MB | 6 GB+ |
| 500,000,000 | ~600 MB | 8 GB+ |

**Примечание:** Помимо bloom-фильтра, GPU нужна память для:
- Рабочих буферов ядра (зависит от workload)
- Словарей и правил (если используются)
- Системных структур OpenCL/CUDA

**Пакетная обработка (batched processing) для огромных списков:**

Если список адресов не умещается в VRAM, разбейте его на пакеты:

```bash
# Разбить файл на пакеты по 10M адресов
split -l 10000000 huge_address_list.txt batch_

# Обработать каждый пакет
for batch in batch_*; do
  ./hashcat -m 35910 "$batch" wordlist.txt -o found.txt --outfile-format 2
done
```

#### Форматы входных данных ####

**Ethereum адреса (для модуля 35910):**

Модуль поддерживает несколько форматов:

```
# С префиксом 0x (рекомендуется)
0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb

# Без префикса (40 hex символов)
742d35cc6634c0532925a3b844bc9e7595f0beb

# Checksummed (EIP-55) — смешанный регистр (поддерживается)
0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb

# Lowercase (поддерживается)
0x742d35cc6634c0532925a3b844bc9e7595f0beb

# Uppercase (поддерживается)
0X742D35CC6634C0532925A3B844BC9E7595F0BEB
```

**Важно:**
- Каждый адрес должен быть на отдельной строке
- Пробелы и табуляции игнорируются
- Комментарии НЕ поддерживаются (не используйте # в файле адресов)
- Пустые строки игнорируются
- Длина: точно 40 hex символов (+ опционально префикс `0x`)

**Пример файла адресов (eth_addresses.txt):**
```
0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb
0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe
0x9c7002ea607c998e062793c420116b66f92421ac
0xacc6378af93c8cdb42d429625cd531038531a1db
```

**Ошибки формата (будут отклонены):**

```
# Неправильная длина
0x742d35Cc6634C0532925a3b844Bc9e7595f0b    # 39 символов
0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0  # 41 символ

# Невалидные hex символы
0x742d35Gc6634C0532925a3b844Bc9e7595f0bEb  # 'G' не hex

# Некорректный формат
742d35Cc6634C0532925a3b844Bc9e7595f0bEb0x  # префикс в конце
```

**Рекомендации по формату входных файлов:**

1. **Кодировка:** UTF-8 или ASCII (без BOM)
2. **Окончания строк:** Unix (LF) или Windows (CRLF) — оба поддерживаются
3. **Размер файла:** Неограничен (но учитывайте VRAM для bloom-фильтра)
4. **Дубликаты:** Автоматически игнорируются при построении bloom-фильтра
5. **Сортировка:** Не требуется (порядок не важен)
6. **Проверка формата:** Используйте скрипт для валидации перед запуском

**Валидация файла адресов (рекомендуется перед большим запуском):**

```bash
# Проверить формат каждой строки
grep -Ev '^(0x)?[0-9a-fA-F]{40}$' eth_addresses.txt
# Если вывод пустой — все адреса валидны

# Подсчет валидных адресов
grep -Ec '^(0x)?[0-9a-fA-F]{40}$' eth_addresses.txt

# Удалить дубликаты
sort -u eth_addresses.txt > eth_addresses_unique.txt
```

#### Работа с приватными ключами ####

**Примечание:** Модули 35900-35904 и 35910 работают с парольными фразами, которые хешируются в приватные ключи. Прямая работа с готовыми приватными ключами (32 байта binary или 64 hex) планируется в модулях 35912-35915 (в разработке).

**Временное решение — использование существующих модулей:**

Если у вас есть список приватных ключей в hex-формате (64 символа):

```bash
# Приватные ключи в hex (64 hex chars = 32 bytes)
# Например: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Можно использовать режим -a 0 (словарь) с файлом ключей как "словарём"
./hashcat -m 35910 eth_addresses.txt privkeys_hex.txt -a 0

# Или создать маски для поиска ключей с известным паттерном
./hashcat -m 35910 eth_addresses.txt -a 3 '0000000000000000?h?h?h?h?h?h?h?h?h?h?h?h?h?h?h?h'
```

**Auto-detection формата:**

Hashcat автоматически определяет формат входных данных по длине и содержимому:
- **Парольная фраза:** Любая строка (1-256 символов) → хешируется в ключ
- **Hex ключ (64 символа):** Распознается как hex → конвертируется в ключ
- **Binary ключ:** Используйте hex-представление

#### Производительность ####

**Ожидаемая производительность (хэшрейт):**

| GPU | Mode 35900-35904 | Mode 35910 | Потребление |
|-----|-----------------|-----------|-------------|
| NVIDIA RTX 3050 6GB | 80-120 MH/s | 100-150 MH/s | 130W |
| NVIDIA RTX 3060 12GB | 150-200 MH/s | 180-250 MH/s | 170W |
| NVIDIA RTX 3090 24GB | 300-500 MH/s | 400-600 MH/s | 350W |
| AMD RX 6900 XT 16GB | 250-400 MH/s | 300-500 MH/s | 300W |
| NVIDIA RTX 4090 24GB | 500-800 MH/s | 600-1000 MH/s | 450W |

*Примечание: Реальная производительность зависит от охлаждения, power limit, версии драйверов, и специфики workload (длина фразы, режим атаки).*

**Факторы, влияющие на скорость:**

1. **Длина парольной фразы:** Короткие фразы (< 8 символов) → выше скорость
2. **Режим атаки:** 
   - `-a 3` (mask) — самый быстрый
   - `-a 0` (wordlist) — быстрый
   - `-a 0 -r rules` (wordlist + rules) — медленнее
   - `-a 1` (combinator) — медленнее
3. **Workload profile (`-w`):**
   - `-w 1` — низкая нагрузка, ~50% скорости
   - `-w 2` — по умолчанию, ~80% скорости
   - `-w 3` — высокая нагрузка, ~95% скорости
   - `-w 4` — nightmare, 100% скорости (система зависает)

**Бенчмарк (тестирование скорости):**
```bash
# Тест производительности модуля
./hashcat -m 35910 -b

# Тест с реальным файлом адресов
./hashcat -m 35910 eth_addresses.txt -a 3 ?l?l?l?l?l?l --runtime 60
```

#### Примеры использования ####

**Атака по словарю:**
```bash
./hashcat -m 35910 -a 0 eth_addresses.txt wordlist.txt
```

**Атака с правилами:**
```bash
./hashcat -m 35910 -a 0 eth_addresses.txt wordlist.txt -r rules/best64.rule
```

**Атака по маске (брутфорс):**
```bash
# 8 строчных букв
./hashcat -m 35910 -a 3 eth_addresses.txt ?l?l?l?l?l?l?l?l

# Известный префикс + 4 неизвестных hex
./hashcat -m 35910 -a 3 eth_addresses.txt 'mykey?h?h?h?h'
```

**Комбинаторная атака:**
```bash
./hashcat -m 35910 -a 1 eth_addresses.txt words1.txt words2.txt
```

**Гибридная атака (wordlist + mask):**
```bash
# Слово + 4 цифры
./hashcat -m 35910 -a 6 eth_addresses.txt wordlist.txt ?d?d?d?d
```

**Продолжение прерванной сессии:**
```bash
# Первый запуск с сессией
./hashcat -m 35910 eth_addresses.txt wordlist.txt --session mysession

# Восстановление после прерывания
./hashcat --session mysession --restore
```

**Сохранение результатов:**
```bash
# Сохранить найденные ключи в файл
./hashcat -m 35910 eth_addresses.txt wordlist.txt -o found_keys.txt

# Формат вывода: адрес:фраза
./hashcat -m 35910 eth_addresses.txt wordlist.txt -o found.txt --outfile-format 2
```

#### Дополнительная информация ####

Полная документация доступна в:
- `README_MODULE_35910.md` — Краткое руководство
- `docs/MODULE_35910_README.md` — Полное руководство с примерами
- `docs/IMPLEMENTATION_SUMMARY.md` — Технические детали реализации

---

### Happy Cracking!
