# WhatsApp Stream Crypto Library

Библиотека для шифрования и расшифровки медиа файлов в формате, совместимом с WhatsApp. Поддерживает потоковую обработку данных и проверку целостности.

## ✅ Статус проекта

**Все основные проблемы решены!** Библиотека полностью функциональна и готова к использованию в продакшене.

**Протестированные форматы:**
- ✅ **AUDIO**: 16111 байт - работает корректно
- ✅ **IMAGE**: 54211 байт - работает корректно  
- ✅ **VIDEO**: 393736 байт - работает корректно

## Возможности

- ✅ **Шифрование/расшифровка медиа файлов** (аудио, видео, изображения)
- ✅ **Потоковая обработка данных** с минимальным использованием памяти
- ✅ **Проверка целостности данных** через HMAC-SHA256
- ✅ **Поддержка генерации sidecar файлов** для потокового воспроизведения
- ✅ **Полная совместимость** с форматом шифрования WhatsApp
- ✅ **Использование встроенных функций PHP** (hash_hkdf с PHP 7.1+)
- ✅ **Правильная обработка паддинга** в AES-256-CBC режиме

## Требования

- PHP 7.1+ (для поддержки встроенной функции `hash_hkdf()`)
- OpenSSL расширение
- Composer

## Установка

```bash
composer require whatsapp/stream-crypto
```

## Использование

### Расшифровка файла

```php
use WhatsAppStream\Crypto\CryptoManager;
use WhatsAppStream\Enum\MediaType;
use WhatsAppStream\Stream\DecryptingStream;

$cryptoManager = new CryptoManager();
$encryptedStream = new \GuzzleHttp\Psr7\Stream(fopen('encrypted.mp4', 'r'));
$mediaKey = file_get_contents('media.key');

$decryptingStream = new DecryptingStream(
    $encryptedStream,
    $mediaKey,
    MediaType::VIDEO,
    $cryptoManager
);

$targetHandle = fopen('decrypted.mp4', 'wb');
while (!$decryptingStream->eof()) {
    fwrite($targetHandle, $decryptingStream->read(65536));
}
fclose($targetHandle);
$decryptingStream->close();
```

### Шифрование файла

```php
use WhatsAppStream\Stream\EncryptingStream;

$mediaKey = random_bytes(32);
$sourceStream = new \GuzzleHttp\Psr7\Stream(fopen('video.mp4', 'r'));

$encryptingStream = new EncryptingStream(
    $sourceStream,
    $mediaKey,
    MediaType::VIDEO,
    $cryptoManager
);

$targetHandle = fopen('encrypted.mp4', 'wb');
while (!$encryptingStream->eof()) {
    fwrite($targetHandle, $encryptingStream->read(65536));
}
fclose($targetHandle);
$encryptingStream->close();
```

## Запуск тестов

Библиотека содержит набор функциональных тестов для проверки работы с различными типами медиа файлов:

```bash
# Основные тесты расшифровки (рекомендуется)
./vendor/bin/phpunit tests/functional/DecryptionTest.php

# Все тесты включая шифрование
./vendor/bin/phpunit tests/

# Отдельные тесты
php tests/functional/EncryptionTest.php     # Тест шифрования
php tests/functional/SidecarTest.php       # Тест генерации sidecar
```

**Результат тестов:**
```
Testing AUDIO decryption: ✅ Successfully decrypted AUDIO file (16111 bytes)
Testing IMAGE decryption: ✅ Successfully decrypted IMAGE file (54211 bytes)  
Testing VIDEO decryption: ✅ Successfully decrypted VIDEO file (393736 bytes)

All tests passed successfully!
```

## 🔧 Исправленные проблемы

В данной версии исправлены все критические проблемы:

1. ✅ **HKDF реализация** → Используется встроенная `hash_hkdf()` PHP 7.1+
2. ✅ **Проблема с памятью** → MAC проверяется потоково без загрузки всего файла
3. ✅ **Обработка паддинга** → Корректная работа с `OPENSSL_ZERO_PADDING`
4. ✅ **Единая подпись** → HMAC вычисляется один раз для всех данных
5. ✅ **Структура файла** → IV добавляется в начало в `EncryptingStream`

## 📖 Примеры использования

Все примеры кода находятся в рабочих тестах:

### Расшифровка файлов
**Полный пример:** [`tests/functional/DecryptionTest.php`](tests/functional/DecryptionTest.php)

```php
// Базовое использование DecryptingStream
$cryptoManager = new CryptoManager();
$encryptedStream = new Stream(fopen($encryptedPath, 'r'), $fileSize);
$mediaKey = file_get_contents($keyPath);

$decryptingStream = new DecryptingStream(
    $encryptedStream,
    $mediaKey,
    MediaType::VIDEO,
    $cryptoManager
);

// Читаем расшифрованные данные
$decryptedData = '';
while (!$decryptingStream->eof()) {
    $decryptedData .= $decryptingStream->read(65536);
}
```

### Шифрование файлов
**Полный пример:** [`tests/functional/EncryptionTest.php`](tests/functional/EncryptionTest.php)

```php
// Базовое использование EncryptingStream
$mediaKey = random_bytes(32);
$sourceStream = new Stream(fopen($sourcePath, 'r'));

$encryptingStream = new EncryptingStream(
    $sourceStream,
    $mediaKey,
    MediaType::AUDIO,
    $cryptoManager
);

// Записываем зашифрованные данные
$encryptedData = '';
while (!$encryptingStream->eof()) {
    $encryptedData .= $encryptingStream->read(65536);
}
```

### Генерация Sidecar файлов
**Полный пример:** [`tests/functional/SidecarTest.php`](tests/functional/SidecarTest.php)

```php
// Генерация sidecar для потокового воспроизведения
$sidecarGenerator = new SidecarGenerator($cryptoManager);
$encryptedStream = new Stream(fopen($encryptedPath, 'r'));

$sidecarData = $sidecarGenerator->generate(
    $encryptedStream,
    $mediaKey,
    MediaType::VIDEO
);

// Каждые 10 байт = MAC для 64KB чанка
$macCount = strlen($sidecarData) / 10;
```

## Структура проекта

```
src/
  ├── Crypto/
  │   └── CryptoManager.php      # Криптографические операции
  ├── Stream/
  │   ├── DecryptingStream.php   # Поток для расшифровки
  │   └── EncryptingStream.php   # Поток для шифрования
  └── Enum/
      └── MediaType.php          # Типы медиа файлов

tests/
  ├── data/                      # Тестовые файлы
  └── functional/                # Функциональные тесты
```

## Безопасность

- Используется AES-256-CBC для шифрования
- HMAC-SHA256 для проверки целостности  
- HKDF для расширения ключей
- Все криптографические операции выполняются через проверенные функции OpenSSL

## Производительность

- Потоковая обработка с настраиваемым размером буфера (по умолчанию 64KB)
- Минимальное использование памяти
- Поддержка файлов любого размера

## Лицензия

MIT

## Подробная документация

Подробное описание архитектуры и принципов работы библиотеки доступно в файле [ARCHITECTURE.md](ARCHITECTURE.md). 