<?php

namespace WhatsAppStream\Stream;

use Psr\Http\Message\StreamInterface;
use WhatsAppStream\Crypto\CryptoManager;
use WhatsAppStream\Enum\MediaType;

/**
 * Потоковый декоратор для шифрования данных.
 * Реализует построчное чтение и шифрование данных для эффективного использования памяти.
 */
class EncryptingStream implements StreamInterface
{
    private const CHUNK_SIZE = 8192; // Размер чанка для чтения (8KB)
    
    private StreamInterface $sourceStream;
    private CryptoManager $cryptoManager;
    private string $mediaKey;
    private MediaType $mediaType;
    private ?array $expandedKey = null;
    private string $buffer = '';
    private bool $isEof = false;
    private int $position = 0;
    private bool $isInitialized = false;
    private $hmacContext = null;
    private bool $ivWritten = false;
    private bool $macWritten = false;

    /**
     * @param StreamInterface $stream Исходный поток с данными
     * @param string $mediaKey 32-байтный ключ для шифрования
     * @param MediaType $mediaType Тип медиа для контекстной информации HKDF
     * @param CryptoManager $cryptoManager Менеджер криптографических операций
     */
    public function __construct(
        StreamInterface $stream,
        string $mediaKey,
        MediaType $mediaType,
        CryptoManager $cryptoManager
    ) {
        $this->sourceStream = $stream;
        $this->mediaKey = $mediaKey;
        $this->mediaType = $mediaType;
        $this->cryptoManager = $cryptoManager;
    }

    /**
     * Инициализирует криптографические ключи при первом использовании
     */
    private function initializeKeys(): void
    {
        if ($this->expandedKey === null) {
            $this->expandedKey = $this->cryptoManager->expandMediaKey($this->mediaKey, $this->mediaType);
            $this->hmacContext = hash_init('sha256', HASH_HMAC, $this->expandedKey['macKey']);
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
        $this->sourceStream->close();
    }

    /**
     * Отсоединяет базовый ресурс потока
     */
    public function detach()
    {
        return $this->sourceStream->detach();
    }

    /**
     * Возвращает размер потока
     * Всегда возвращает null, так как размер зашифрованных данных
     * отличается от размера исходных данных
     */
    public function getSize(): ?int
    {
        return null;
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
        return false; // Шифрующий поток не поддерживает seek
    }

    /**
     * Устанавливает указатель на определенную позицию в потоке
     */
    public function seek($offset, $whence = SEEK_SET): void
    {
        throw new \RuntimeException('Encrypting stream is not seekable');
    }

    /**
     * Перемещает указатель в начало потока
     */
    public function rewind(): void
    {
        throw new \RuntimeException('Encrypting stream is not seekable');
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
        throw new \RuntimeException('Stream is read-only');
    }

    /**
     * Проверяет, можно ли читать из потока
     */
    public function isReadable(): bool
    {
        return true;
    }

    /**
     * Читает и шифрует данные из потока
     * 
     * @param int $length Количество байт для чтения
     * @return string Зашифрованные данные
     */
    public function read($length): string
    {
        $this->initializeKeys();

        // Если в буфере достаточно данных, возвращаем их
        if (strlen($this->buffer) >= $length) {
            $result = substr($this->buffer, 0, $length);
            $this->buffer = substr($this->buffer, $length);
            $this->position += $length;
            return $result;
        }

        // Добавляем IV в начало если еще не добавлен
        if (!$this->ivWritten) {
            hash_update($this->hmacContext, $this->expandedKey['iv']);
            $this->buffer .= $this->expandedKey['iv'];
            $this->ivWritten = true;
            return $this->read($length);
        }

        // Если исходный поток не закончился, читаем и шифруем
        if (!$this->sourceStream->eof()) {
            $chunk = $this->sourceStream->read(self::CHUNK_SIZE);
            if (!empty($chunk)) {
                // Добавляем паддинг к последнему блоку если нужно
                if ($this->sourceStream->eof()) {
                    $blockSize = 16; // AES block size
                    $paddingLength = $blockSize - (strlen($chunk) % $blockSize);
                    $chunk .= str_repeat(chr($paddingLength), $paddingLength);
                }

                $encrypted = openssl_encrypt(
                    $chunk,
                    'aes-256-cbc',
                    $this->expandedKey['cipherKey'],
                    OPENSSL_RAW_DATA,
                    $this->expandedKey['iv']
                );

                if ($encrypted === false) {
                    throw new \RuntimeException('Encryption failed');
                }

                hash_update($this->hmacContext, $encrypted);
                $this->buffer .= $encrypted;
                return $this->read($length);
            }
        }

        // Если исходный поток закончился и MAC еще не добавлен
        if (!$this->macWritten && $this->sourceStream->eof()) {
            $mac = substr(hash_final($this->hmacContext, true), 0, 10); // Усекаем до 10 байт
            $this->buffer .= $mac;
            $this->macWritten = true;
            return $this->read($length);
        }

        // Если все данные обработаны
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
        return $this->sourceStream->getMetadata($key);
    }
} 