# WhatsApp Stream Crypto Library

Библиотека для шифрования и расшифровки медиа файлов в формате, совместимом с WhatsApp. Поддерживает потоковую обработку данных и проверку целостности.

## Возможности

- Шифрование/расшифровка медиа файлов (аудио, видео, изображения)
- Потоковая обработка данных с минимальным использованием памяти
- Проверка целостности данных через MAC
- Поддержка генерации sidecar файлов для потокового воспроизведения
- Совместимость с форматом шифрования WhatsApp

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
```

## Запуск тестов

Библиотека содержит набор функциональных тестов для проверки работы с различными типами медиа файлов:

```bash
# Тест расшифровки файлов
php tests/functional/DecryptionTest.php

# Тест шифрования файлов
php tests/functional/EncryptionTest.php

# Тест генерации sidecar файлов
php tests/functional/SidecarTest.php
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

## Лицензия

MIT

## Подробная документация

Подробное описание архитектуры и принципов работы библиотеки доступно в файле [ARCHITECTURE.md](ARCHITECTURE.md). 