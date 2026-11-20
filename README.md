# SecureLinux-Audit

Автономная check-only сборка аудита конфигурации Linux по требованиям ФСТЭК.
Один исполняемый bash-файл с встроенными адаптерами проверок: без установки,
без зависимостей сверх штатного `python3` и типовых системных утилит.

Версия: 1.0.9 · Статус: RELEASE · Вариант: check-only

## Что это

Check-only артефакт: производная сборка исходного корпуса (цепочка
воспроизводства: `tools/strip-checkonly-v3.py`). Проверки только читают
конфигурацию системы и выдают отчёт.

## Что осталось

- 86 контролей: 85 ядра ФСТЭК (`fstec-core`, документы 2022/2025/2026 гг.) +
  1 recommended (`--layer recommended`);
- `--check` с форматами pretty / raw (`SLP-CHECK-V1` TSV) / json / pdf
  (отчёт PDF генерируется самим скриптом: только ASCII в stdout,
  внешних зависимостей сверх `python3` нет);
- `--list`, `--provenance`, `--build-info`, `--version`, `--help`;
- код возврата: 0 = оценка выполнена полностью (итог COMPLIANT или
  NONCOMPLIANT); 1 = оценка не завершена (UNEVALUATED: есть ERROR или
  NOT_FOUND) либо внутренний сбой выполнения/вывода; 2 = ошибка вызова
  (USAGE_ERROR). Чекер не отказывает ни на одной системе: среда вне
  поддерживаемой матрицы помечается `SUPPORT=UNSUPPORTED` в отчёте,
  проверки выполняются в любом случае. Десктопные установки распознаются
  (`TYPE=DESKTOP`, среда `*-x86_64-desktop`) и помечаются `UNSUPPORTED`.
  Нарушения требований видны в итоге `POLICY=NONCOMPLIANT` и строках FAIL.

## Запуск

```bash
sudo ./securelinux-audit.sh --check                    # таблица для пользователя
sudo ./securelinux-audit.sh --check --format json      # машинный отчёт
sudo ./securelinux-audit.sh --check --format raw       # стабильный TSV
sudo ./securelinux-audit.sh --check --format pdf > report.pdf   # PDF-отчёт
sudo ./securelinux-audit.sh --check --failed           # только FAIL/ERROR
sha256sum -c securelinux-audit.sh.sha256               # сверка целостности
```

Проверка только читает состояние системы; запуск возможен и без sudo:
часть контролей тогда даст NOT_FOUND/ERROR из-за прав доступа.

## Гарантии check-only

- аргументы вне задокументированного набора возвращают `USAGE_ERROR`
  (код 2, stdout пуст);
- проверки только читают состояние системы;
- вывод `--check` идентичен исходному продукту (проверено диффом на эталонном
  хосте; единственное расхождение: живые счётчики ресурсов, например
  свободное место раздела аудита).

## Состав репозитория

- `securelinux-audit.sh`: артефакт проверки;
- `securelinux-audit.sh.sha256`: контрольная сумма;
- `tools/`: `strip-checkonly-v3.py` (воспроизводство срезки артефакта 1.0.9),
  `slp-pdf-block-v1.py` (встроенный генератор PDF для `--format pdf`),
  `strip-presentation-template-v1.py` и `build-presentation-audit-v3.py`
  (сборка презентации: шаблон → сверка чисел с данными репозитория → docx),
  манифестные утилиты (`rebuild-root-manifests.py`, `pin-closure.py`, `write-sha256.py`),
  `source_skeleton_generator.py` (генератор блока `source:` для новых контролей),
  `report-render-v1.py` (JSON-отчёт чекера → оформленный docx для конвертации в PDF);
- `docs/`: нормативные справки и политики (см. `docs/README.md`),
  `docs/deployment.md`: пример внедрения: доставка артефакта и сбор отчёта
  через агента управления (на примере Kaspersky Security Center);
- `sources/`, `index/`, `controls/`, `product/`: доказательная база: документы
  ФСТЭК, индекс нормы, YAML-контроли и check-контракты/адаптеры. Поля
  `--provenance` разрешаются в файлы репозитория, кроме `control_sha256` и
  `control_manifest_sha256`: они фиксируют контроли исходной сборки
  до снятия полей `apply` и не совпадают с текущими YAML (см. `docs/README.md`);
- `checker/`: валидаторы корпуса (`gates-v3`, `source-parity-v1`) и
  доказательство release-гейта исходной сборки (`release-v1/`);
- `tests/`: DEV-набор проверок корпуса и целостности (`tests/run-all.py --dev`);
- `presentation/`: презентация продукта (шаблон + docx + PDF) и пример
  оформленного отчёта проверки (`SecureLinux-Audit-report-example-1.0.9.pdf`,
  снят на этом хосте ключом `--format pdf`);
- `SHA256SUMS`, `PROJECT-FILES.sha256`: корневые манифесты отслеживаемых файлов.

Локальные рабочие файлы (`docs/HANDOFF.md`, `AGENTS.md`, `work/`) в репозиторий
не входят: состояние и правила живут на машине разработчика.

## Отношение к исходному проекту

Независимый артефакт и независимый проект: собран одноразовой срезкой,
не входит в конвейер исходного проекта и не зависит от него.

SHA-256 файла `securelinux-audit.sh`:
`cffad585dea00186db3c7911eb2960dac3e28db30e4d5150c54fa87e34bcce44`
