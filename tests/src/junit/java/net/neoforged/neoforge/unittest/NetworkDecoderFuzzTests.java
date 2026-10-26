/*
 * Copyright (c) NeoForged and contributors
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package net.neoforged.neoforge.unittest;

import com.code_intelligence.jazzer.junit.FuzzTest;
import io.netty.buffer.Unpooled;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.function.BiFunction;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.ByteBufCodecs;
import net.minecraft.network.codec.StreamDecoder;
import net.neoforged.neoforge.network.payload.CommonRegisterPayload;
import net.neoforged.neoforge.network.payload.CommonVersionPayload;
import net.neoforged.neoforge.network.payload.KnownRegistryDataMapsReplyPayload;
import net.neoforged.neoforge.network.payload.MinecraftRegisterPayload;
import net.neoforged.neoforge.network.payload.MinecraftUnregisterPayload;
import net.neoforged.neoforge.network.payload.ModdedNetworkQueryPayload;
import net.neoforged.neoforge.network.payload.SplitPacketPayload;

/**
 * Fuzz tests for decoders that read untrusted network input.
 * <p>
 * A decoder may reject malformed input by throwing an exception, which disconnects the sender.
 * It must never throw an {@link Error} (such as {@link OutOfMemoryError} or {@link StackOverflowError}),
 * and must not allocate memory out of proportion to the input it was given (CWE-789).
 * <p>
 * When run as part of {@code junitTest}, each test only replays the inputs stored under
 * {@code NetworkDecoderFuzzTestsInputs/<method>/} in the junit resources.
 * To fuzz, set {@code JAZZER_FUZZ=1} and select a single test, for example:
 *
 * <pre>
 * JAZZER_FUZZ=1 ./gradlew :tests:junitTest --tests '*NetworkDecoderFuzzTests.payloads'
 * </pre>
 *
 * Inputs that trigger a failure are written to the inputs directory, so they are replayed on every later run.
 * The first byte of every input selects the decoder; the remaining bytes are the buffer contents.
 */
public class NetworkDecoderFuzzTests {
    /** Allocation allowed regardless of input size. */
    private static final long BASE_ALLOCATION_BUDGET = 16 * 1024 * 1024;
    /** Additional allocation allowed per input byte. */
    private static final long ALLOCATION_BUDGET_PER_BYTE = 1024;

    private static final BiFunction<FriendlyByteBuf, Integer, Integer> VAR_INT_VALUE = (buf, key) -> buf.readVarInt();

    /**
     * Payloads the server decodes from a client: serverbound payloads and those accepted before channel negotiation.
     */
    private static final List<StreamDecoder<FriendlyByteBuf, ?>> PAYLOADS = List.of(
            MinecraftRegisterPayload.STREAM_CODEC,
            MinecraftUnregisterPayload.STREAM_CODEC,
            ModdedNetworkQueryPayload.STREAM_CODEC,
            CommonVersionPayload.STREAM_CODEC,
            CommonRegisterPayload.STREAM_CODEC,
            KnownRegistryDataMapsReplyPayload.STREAM_CODEC,
            SplitPacketPayload.STREAM_CODEC);

    /**
     * Length-prefixed primitives that payload codecs, including those of mods, are built from.
     * Keep the order stable: stored inputs refer to these by index.
     */
    private static final List<StreamDecoder<FriendlyByteBuf, ?>> PRIMITIVES = List.of(
            buf -> buf.readList(ByteBufCodecs.VAR_INT),
            buf -> buf.readCollection(ArrayList::new, ByteBufCodecs.VAR_INT),
            buf -> buf.readMap(HashMap::new, ByteBufCodecs.VAR_INT, ByteBufCodecs.VAR_INT),
            buf -> ByteBufCodecs.VAR_INT.apply(ByteBufCodecs.list()).decode(buf),
            buf -> ByteBufCodecs.map(HashMap::new, ByteBufCodecs.VAR_INT, ByteBufCodecs.VAR_INT).decode(buf),
            FriendlyByteBuf::readByteArray,
            FriendlyByteBuf::readVarIntArray,
            // NeoForge extensions
            buf -> buf.readArray(Integer[]::new, ByteBufCodecs.VAR_INT),
            buf -> buf.readMap(ByteBufCodecs.VAR_INT, VAR_INT_VALUE));

    @FuzzTest
    void payloads(byte[] input) {
        decode(PAYLOADS, input);
    }

    @FuzzTest
    void primitives(byte[] input) {
        decode(PRIMITIVES, input);
    }

    private static void decode(List<StreamDecoder<FriendlyByteBuf, ?>> decoders, byte[] input) {
        if (input.length == 0) {
            return;
        }
        var decoder = decoders.get(Byte.toUnsignedInt(input[0]) % decoders.size());
        var buf = new FriendlyByteBuf(Unpooled.wrappedBuffer(input, 1, input.length - 1));

        var threadBean = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
        long threadId = Thread.currentThread().threadId();
        long allocatedBefore = threadBean.getThreadAllocatedBytes(threadId);
        try {
            decoder.decode(buf);
        } catch (RuntimeException e) {
            // Rejecting malformed input is fine, it disconnects the sender
        } finally {
            buf.release();
        }
        long allocated = threadBean.getThreadAllocatedBytes(threadId) - allocatedBefore;

        long budget = BASE_ALLOCATION_BUDGET + ALLOCATION_BUDGET_PER_BYTE * input.length;
        if (allocated > budget) {
            throw new AssertionError("Decoding " + input.length + " bytes allocated " + allocated + " bytes, exceeding the budget of " + budget
                    + ". The decoder likely sizes storage from an untrusted length prefix");
        }
    }
}
