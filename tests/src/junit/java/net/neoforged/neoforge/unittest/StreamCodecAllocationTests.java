/*
 * Copyright (c) NeoForged and contributors
 * SPDX-License-Identifier: LGPL-2.1-only
 */

package net.neoforged.neoforge.unittest;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import io.netty.buffer.Unpooled;
import java.lang.management.ManagementFactory;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.stream.Stream;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.ByteBufCodecs;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Guards against CWE-789 (memory allocation with excessive size value) in stream decoders.
 * <p>
 * Each case feeds a decoder a length prefix of {@link Integer#MAX_VALUE} followed by a single valid element,
 * then truncates the input. A safe decoder must fail with an ordinary exception after allocating a bounded
 * amount of memory; an unsafe one sizes its backing storage from the untrusted length and runs out of memory.
 * The single element ensures that lazily-allocated storage (such as a {@link HashMap}'s table) is also exercised.
 */
public class StreamCodecAllocationTests {
    private static final int MALICIOUS_LENGTH = Integer.MAX_VALUE;
    /** Generous upper bound on what decoding one element may allocate. */
    private static final long ALLOCATION_BUDGET = 16 * 1024 * 1024;

    private static final BiFunction<FriendlyByteBuf, Integer, Integer> VAR_INT_VALUE = (buf, key) -> buf.readVarInt();

    private static Stream<Arguments> collectionDecoders() {
        return Stream.of(
                // Vanilla
                arguments("FriendlyByteBuf#readList", (Consumer<FriendlyByteBuf>) buf -> buf.readList(ByteBufCodecs.VAR_INT), 1),
                arguments("FriendlyByteBuf#readCollection", (Consumer<FriendlyByteBuf>) buf -> buf.readCollection(ArrayList::new, ByteBufCodecs.VAR_INT), 1),
                arguments("FriendlyByteBuf#readMap", (Consumer<FriendlyByteBuf>) buf -> buf.readMap(HashMap::new, ByteBufCodecs.VAR_INT, ByteBufCodecs.VAR_INT), 2),
                arguments("ByteBufCodecs#list", (Consumer<FriendlyByteBuf>) buf -> ByteBufCodecs.VAR_INT.apply(ByteBufCodecs.list()).decode(buf), 1),
                arguments("ByteBufCodecs#map", (Consumer<FriendlyByteBuf>) buf -> ByteBufCodecs.map(HashMap::new, ByteBufCodecs.VAR_INT, ByteBufCodecs.VAR_INT).decode(buf), 2),
                arguments("FriendlyByteBuf#readByteArray", (Consumer<FriendlyByteBuf>) FriendlyByteBuf::readByteArray, 1),
                arguments("FriendlyByteBuf#readVarIntArray", (Consumer<FriendlyByteBuf>) FriendlyByteBuf::readVarIntArray, 1),
                // NeoForge extensions
                arguments("IFriendlyByteBufExtension#readArray", (Consumer<FriendlyByteBuf>) buf -> buf.readArray(Integer[]::new, ByteBufCodecs.VAR_INT), 1),
                arguments("IFriendlyByteBufExtension#readMap", (Consumer<FriendlyByteBuf>) buf -> buf.readMap(ByteBufCodecs.VAR_INT, VAR_INT_VALUE), 2));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("collectionDecoders")
    void decoderDoesNotTrustLengthPrefix(String name, Consumer<FriendlyByteBuf> decoder, int varIntsPerElement) {
        var buf = new FriendlyByteBuf(Unpooled.buffer());
        buf.writeVarInt(MALICIOUS_LENGTH);
        for (int i = 0; i < varIntsPerElement; i++) {
            buf.writeVarInt(1);
        }

        var threadBean = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
        long threadId = Thread.currentThread().threadId();
        long allocatedBefore = threadBean.getThreadAllocatedBytes(threadId);
        try {
            assertThrows(RuntimeException.class, () -> decoder.accept(buf), name + " should reject truncated input");
        } catch (OutOfMemoryError e) {
            fail(name + " sized its storage from an untrusted length prefix and ran out of memory", e);
        } finally {
            buf.release();
        }
        long allocated = threadBean.getThreadAllocatedBytes(threadId) - allocatedBefore;

        assertTrue(allocated < ALLOCATION_BUDGET,
                name + " allocated " + allocated + " bytes for a single element; it must cap the initial capacity it derives from the length prefix");
    }
}
