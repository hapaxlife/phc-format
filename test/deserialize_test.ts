import { deserialize } from "../mod.ts";
import sdData from "./fixtures/serialize-deserialize.ts";
import sData from "./fixtures/serialize-only.ts";

import {
  assertEquals,
  assertMatch,
  assertObjectMatch,
  assertThrows,
} from "jsr:@std/assert";

Deno.test("should deserialize correct phc strings", () => {
  sdData.serialized.forEach((_g, i) => {
    assertObjectMatch(
      deserialize(sdData.serialized[i]),
      // @ts-expect-error : type
      sdData.deserialized[i],
    );
  });
});

Deno.test("should deserialize only correct phc strings", () => {
  sData.serialized.forEach((_g, i) => {
    assertObjectMatch(
      deserialize(sData.serialized[i]),
      // @ts-expect-error : type
      sData.deserialized[i],
    );
  });
});

Deno.test("should thow errors if trying to deserialize an invalid phc string", async () => {
  // @ts-expect-error : test null
  let err: Error = await assertThrows(() => deserialize(null)) as Error;
  assertEquals(err.message, "pchstr must be a non-empty string");

  err = await assertThrows(() => deserialize("a$invalid")) as Error;
  assertEquals(err.message, "pchstr must contain a $ as first char");

  err = await assertThrows(() => deserialize("$b$c$d$e$f")) as Error;
  assertEquals(err.message, "pchstr contains too many fields: 5/4");

  err = await assertThrows(() => deserialize("invalid")) as Error;
  assertEquals(err.message, "pchstr must contain a $ as first char");

  err = await assertThrows(() => deserialize("$i_n_v_a_l_i_d")) as Error;
  assertMatch(err.message, /id must satisfy/);

  err = await assertThrows(() => deserialize("$pbkdf2$rounds_=1000")) as Error;
  assertMatch(err.message, /params names must satisfy/);

  err = await assertThrows(() => deserialize("$pbkdf2$rounds=1000@")) as Error;
  assertMatch(err.message, /params values must satisfy/);

  err = await assertThrows(() => deserialize("$pbkdf2$rounds:1000")) as Error;
  assertMatch(err.message, /params must be in the format name=value/);

  err = await assertThrows(() =>
    deserialize("$argon2i$unrecognized$m=120,t=5000,p=2$EkCWX6pSTqWruiR0")
  ) as Error;
  assertMatch(err.message, /pchstr contains unrecognized fields/);

  err = await assertThrows(() =>
    deserialize(
      "$argon2i$unrecognized$v=19$m=120,t=5000,p=2$EkCWX6pSTqWruiR0",
    )
  ) as Error;
  assertEquals(err.message, "pchstr contains too many fields: 5/4");

  err = await assertThrows(() =>
    deserialize(
      "$argon2i$v=19$unrecognized$m=120,t=5000,p=2$EkCWX6pSTqWruiR0",
    )
  ) as Error;
  assertMatch(err.message, /pchstr contains unrecognized fields/);
});
