import { serialize } from "../mod.ts";
import sdData from "./fixtures/serialize-deserialize.ts";
import sData from "./fixtures/serialize-only.ts";

// url_test.ts
import { assertEquals, assertMatch, assertThrows } from "jsr:@std/assert";

const encoder = new TextEncoder();

Deno.test("should serialize only phc objects", () => {
  sData.deserialized.forEach((_g, i) => {
    assertEquals(serialize(sData.deserialized[i]), sData.serialized[i]);
  });
});

Deno.test("should serialize correct phc objects", () => {
  sdData.deserialized.forEach((_g, i) => {
    assertEquals(
      serialize(sdData.deserialized[i]),
      sdData.serialized[i],
    );
  });
});

Deno.test("should thow errors if trying to serialize with invalid arguments", async () => {
  // @ts-expect-error : test null
  let err: Error = await assertThrows(() => serialize(null)) as Error;
  assertEquals(err.message, "opts must be an object");

  // @ts-expect-error : test empty
  err = await assertThrows(() => serialize({})) as Error;
  assertEquals(err.message, "opts is empty");

  err = await assertThrows(() => serialize({ id: "i_n_v_a_l_i_d" })) as Error;
  assertMatch(err.message, /id must satisfy/);

  err = await assertThrows(() =>
    // @ts-expect-error : param null
    serialize({ id: "pbkdf2", params: null })
  ) as Error;
  assertEquals(err.message, "params must be an object");

  err = await assertThrows(() =>
    // @ts-expect-error : param null
    serialize({ id: "pbkdf2", params: { i: {} } })
  ) as Error;
  assertEquals(err.message, "params values must be strings");

  err = await assertThrows(() =>
    serialize({ id: "pbkdf2", params: { rounds_: "1000" } })
  ) as Error;
  assertMatch(err.message, /params names must satisfy/);

  err = await assertThrows(() =>
    serialize({ id: "pbkdf2", params: { rounds: "1000@" } })
  ) as Error;
  assertMatch(err.message, /params values must satisfy/);

  err = await assertThrows(() =>
    // @ts-expect-error : salt
    serialize({ id: "pbkdf2", params: { rounds: "1000" }, salt: "string" })
  ) as Error;
  assertEquals(err.message, "salt must be a Uint8Array");

  err = await assertThrows(() =>
    serialize({ id: "argon2id", version: -10 })
  ) as Error;
  assertEquals(err.message, "version must be a positive integer number");

  err = await assertThrows(() =>
    serialize({
      id: "pbkdf2",
      params: { rounds: "1000" },
      salt: encoder.encode("string"),
      // @ts-expect-error : param null
      hash: "string",
    })
  ) as Error;
  assertEquals(err.message, "hash must be a Uint8Array");
});
