<?php

namespace WhatsAppStream\Stream;

use Psr\Http\Message\StreamInterface;
use RuntimeException;
use WhatsAppStream\Crypto\CryptoManager;
use WhatsAppStream\Enum\MediaType;

/**
 * Потоковый декоратор для расшифровки данных.
 * Реализует построчное чтение и расшифровку данных для эффективного использования памяти.
 */
class DecryptingStream implements StreamInterface
{
    private const CHUNK_SIZE = 65536; // Размер чанка для чтения (64KB)
    private const MAC_LENGTH = 10;

    private StreamInterface $stream;
    private CryptoManager $cryptoManager;
    private string $mediaKey;
    private MediaType $mediaType;
    private ?array $expandedKey = null;
    private string $buffer = '';
    private bool $isEof = false;
    private int $position = 0;
    private bool $macVerified = false;
    private ?string $lastIv = null;

    /**
     * @param StreamInterface $stream Зашифрованный поток с данными
     * @param string $mediaKey 32-байтный ключ для расшифровки
     * @param MediaType $mediaType Тип медиа для контекстной информации HKDF
     * @param CryptoManager $cryptoManager Менеджер криптографических операций
     */
    public function __construct(
        StreamInterface $stream,
        string $mediaKey,
        MediaType $mediaType,
        CryptoManager $cryptoManager
    ) {
        $this->stream = $stream;
        $this->mediaKey = $mediaKey;
        $this->mediaType = $mediaType;
        $this->cryptoManager = $cryptoManager;
    }

    /**
     * Инициализирует криптографические ключи и проверяет MAC
     */
    private function initialize(): void
    {
        if ($this->expandedKey === null) {
            $this->expandedKey = $this->cryptoManager->expandMediaKey($this->mediaKey, $this->mediaType);
        }

        if (!$this->macVerified) {
            // Сохраняем текущую позицию
            $currentPosition = $this->stream->tell();

            // Читаем MAC из конца файла
            $this->stream->seek(-self::MAC_LENGTH, SEEK_END);
            $mac = $this->stream->read(self::MAC_LENGTH);

            // Получаем размер зашифрованных данных
            $encryptedSize = $this->stream->getSize() - self::MAC_LENGTH;

            // Читаем все зашифрованные данные
            $this->stream->seek(0);
            $encryptedData = $this->stream->read($encryptedSize);

            // Проверяем MAC
            if (!$this->cryptoManager->verifyMac(
                $this->expandedKey['iv'] . $encryptedData,
                $mac,
                $this->expandedKey['macKey']
            )) {
                throw new RuntimeException('MAC verification failed');
            }

            // Возвращаемся к исходной позиции
            $this->stream->seek($currentPosition);
            $this->macVerified = true;
        }
    }

    /**
     * Преобразует поток в строку
     * В случае ошибки возвращает пустую строку
     */
    public function __toString(): string
    {
        try {
            return $this->getContents();
        } catch (\Exception $e) {
            return '';
        }
    }

    /**
     * Закрывает поток и освобождает ресурсы
     */
    public function close(): void
    {
        $this->stream->close();
    }

    /**
     * Отсоединяет базовый ресурс потока
     */
    public function detach()
    {
        return $this->stream->detach();
    }

    /**
     * Возвращает размер потока
     * Размер расшифрованных данных = размер зашифрованных данных - MAC_LENGTH
     */
    public function getSize(): ?int
    {
        $encryptedSize = $this->stream->getSize();
        if ($encryptedSize === null) {
            return null;
        }
        return $encryptedSize - self::MAC_LENGTH;
    }

    /**
     * Возвращает текущую позицию в потоке
     */
    public function tell(): int
    {
        return $this->position;
    }

    /**
     * Проверяет, достигнут ли конец потока
     */
    public function eof(): bool
    {
        return $this->isEof;
    }

    /**
     * Проверяет, поддерживает ли поток произвольный доступ
     */
    public function isSeekable(): bool
    {
        return $this->stream->isSeekable();
    }

    /**
     * Устанавливает указатель на определенную позицию в потоке
     */
    public function seek($offset, $whence = SEEK_SET): void
    {
        if (!$this->isSeekable()) {
            throw new RuntimeException('Stream is not seekable');
        }
        
        $this->stream->seek($offset, $whence);
        $this->position = $this->stream->tell();
        $this->buffer = '';
        $this->lastIv = null;
    }

    /**
     * Перемещает указатель в начало потока
     */
    public function rewind(): void
    {
        $this->lastIv = null;
        $this->seek(0);
    }

    /**
     * Проверяет, можно ли записывать в поток
     */
    public function isWritable(): bool
    {
        return false;
    }

    /**
     * Записывает данные в поток
     */
    public function write($string): int
    {
        throw new RuntimeException('Stream is read-only');
    }

    /**
     * Проверяет, можно ли читать из потока
     */
    public function isReadable(): bool
    {
        return true;
    }

    /**
     * Читает и расшифровывает данные из потока
     */
    public function read($length): string
    {
        $this->initialize();

        // Если в буфере достаточно данных, возвращаем их
        if (strlen($this->buffer) >= $length) {
            $result = substr($this->buffer, 0, $length);
            $this->buffer = substr($this->buffer, $length);
            $this->position += $length;
            return $result;
        }

        // Читаем новый чанк данных
        $chunk = $this->stream->read(min(self::CHUNK_SIZE, $this->getSize() - $this->stream->tell()));
        if (empty($chunk)) {
            if (strlen($this->buffer) > 0) {
                $result = $this->buffer;
                $this->buffer = '';
                $this->position += strlen($result);
                $this->isEof = true;
                return $result;
            }
            $this->isEof = true;
            return '';
        }

        // Используем правильный IV для текущего блока
        $currentIv = $this->lastIv ?? $this->expandedKey['iv'];
        
        // Сохраняем последний блок шифртекста как IV для следующего блока
        $this->lastIv = substr($chunk, -16);

        // Расшифровываем данные
        $decrypted = $this->cryptoManager->decrypt(
            $chunk,
            $currentIv,
            $this->expandedKey['cipherKey']
        );

        if ($decrypted === false) {
            throw new RuntimeException('Decryption failed');
        }

        // Если это последний чанк, удаляем паддинг
        $encryptedDataSize = $this->stream->getSize() - self::MAC_LENGTH;
        if ($this->stream->tell() >= $encryptedDataSize) {
            $padLength = ord($decrypted[strlen($decrypted) - 1]);
            if ($padLength > 0 && $padLength <= 16) {
                $decrypted = substr($decrypted, 0, -$padLength);
            }
        }

        // Добавляем расшифрованные данные в буфер
        $this->buffer .= $decrypted;

        // Рекурсивно вызываем read для получения запрошенного количества данных
        return $this->read($length);
    }

    /**
     * Читает все оставшиеся данные из потока
     */
    public function getContents(): string
    {
        $contents = '';
        while (!$this->eof()) {
            $contents .= $this->read(self::CHUNK_SIZE);
        }
        return $contents;
    }

    /**
     * Возвращает метаданные потока
     */
    public function getMetadata($key = null)
    {
        return $this->stream->getMetadata($key);
    }
} 