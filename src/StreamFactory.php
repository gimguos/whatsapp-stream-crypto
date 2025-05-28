<?php

namespace WhatsAppStream;

use Psr\Http\Message\StreamInterface;
use WhatsAppStream\Crypto\CryptoManager;
use WhatsAppStream\Enum\MediaType;
use WhatsAppStream\Stream\DecryptingStream;
use WhatsAppStream\Stream\EncryptingStream;

/**
 * Фабрика для создания шифрующих и расшифровывающих потоков
 * Предоставляет удобный интерфейс для работы с потоками
 */
class StreamFactory
{
    private CryptoManager $cryptoManager;

    public function __construct()
    {
        $this->cryptoManager = new CryptoManager();
    }

    /**
     * Создает поток для шифрования данных
     *
     * @param StreamInterface $stream Исходный поток с данными
     * @param string $mediaKey 32-байтный ключ для шифрования
     * @param MediaType $mediaType Тип медиа для контекстной информации HKDF
     * @return StreamInterface Поток, который шифрует данные при чтении
     */
    public function createEncryptingStream(
        StreamInterface $stream,
        string $mediaKey,
        MediaType $mediaType
    ): StreamInterface {
        return new EncryptingStream($stream, $mediaKey, $mediaType, $this->cryptoManager);
    }

    /**
     * Создает поток для расшифровки данных
     *
     * @param StreamInterface $stream Зашифрованный поток с данными
     * @param string $mediaKey 32-байтный ключ для расшифровки
     * @param MediaType $mediaType Тип медиа для контекстной информации HKDF
     * @return StreamInterface Поток, который расшифровывает данные при чтении
     */
    public function createDecryptingStream(
        StreamInterface $stream,
        string $mediaKey,
        MediaType $mediaType
    ): StreamInterface {
        return new DecryptingStream($stream, $mediaKey, $mediaType, $this->cryptoManager);
    }

    /**
     * Генерирует информацию для стриминга (sidecar)
     *
     * @param string $data Данные для генерации sidecar
     * @param string $mediaKey 32-байтный ключ
     * @param MediaType $mediaType Тип медиа для контекстной информации HKDF
     * @return string Сгенерированный sidecar (последовательность MAC'ов)
     */
    public function generateStreamingSidecar(string $data, string $mediaKey, MediaType $mediaType): string
    {
        $keys = $this->cryptoManager->expandMediaKey($mediaKey, $mediaType);
        return $this->cryptoManager->generateStreamingSidecar($data, $keys['macKey']);
    }
} 