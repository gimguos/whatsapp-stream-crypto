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
    
    private StreamInterface $stream;
    private CryptoManager $cryptoManager;
    private string $mediaKey;
    private MediaType $mediaType;
    private ?array $expandedKey = null;
    private string $buffer = '';
    private bool $isEof = false;
    private int $position = 0;
    private ?int $currentChunkSize = null;

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
        $this->stream = $stream;
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
        return $this->stream->isSeekable();
    }

    /**
     * Устанавливает указатель на определенную позицию в потоке
     */
    public function seek($offset, $whence = SEEK_SET): void
    {
        if (!$this->isSeekable()) {
            throw new \RuntimeException('Stream is not seekable');
        }
        
        $this->stream->seek($offset, $whence);
        $this->position = $this->stream->tell();
        $this->buffer = '';
    }

    /**
     * Перемещает указатель в начало потока
     */
    public function rewind(): void
    {
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
     * @return string Зашифрованные данные с добавленным MAC
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

        // Читаем новый чанк данных
        $chunk = $this->stream->read(self::CHUNK_SIZE);
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

        // Шифруем чанк
        $encrypted = $this->cryptoManager->encrypt(
            $chunk,
            $this->expandedKey['iv'],
            $this->expandedKey['cipherKey']
        );

        // Вычисляем MAC для зашифрованного чанка
        $mac = $this->cryptoManager->calculateMac(
            $this->expandedKey['iv'] . $encrypted,
            $this->expandedKey['macKey']
        );

        // Добавляем зашифрованные данные и MAC в буфер
        $this->buffer .= $encrypted . $mac;

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