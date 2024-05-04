import { decodeBase64, encodeBase64 } from "./deps.ts";

const idRegex = /^[a-z0-9-]{1,32}$/;
const nameRegex = /^[a-z0-9-]{1,32}$/;
const valueRegex = /^[a-zA-Z0-9\+.-]+$/;
const b64Regex = /^[a-zA-Z0-9\+\/]*={0,2}$/;
const decimalRegex = /^((-)?[1-9]\d*|0)$/;
const versionRegex = /^v=(\d+)$/;

export interface PhcOptions
  extends Partial<Record<string, string | number | Uint8Array | Params>> {
  // Symbolic name for the function.
  id: string;
  // The version of the function.
  version?: number;
  // Parameters of the function.
  params?: Record<string, string | number>;
  // The salt as a Uint8Array.
  salt?: Uint8Array;
  // The hash as a Uint8Array.
  hash?: Uint8Array;
}

type Params = Record<string, string | number>;

/**
 * Object to string separate by , & =
 * @param obj object
 * @returns
 */
function objToKeyVal(obj: Record<string, string | number>): string {
  return objectKeys(obj)
    .map((k) => [k, obj[k]].join("="))
    .join(",");
}

/**
 * string to object separate by , & =
 * @param str string to
 * @returns
 */
function keyValtoObj(str: string): Record<string, string | number> {
  const obj: Record<string, string | number> = {};
  str.split(",").forEach((ps) => {
    const pss = ps.split("=");
    if (pss.length < 2) {
      throw new TypeError(`params must be in the format name=value`);
    }
    const key = pss.shift();
    if (key !== undefined) {
      obj[key] = pss.join("=");
    }
  });
  return obj;
}

/**
 * Keys of an object
 * @param object Keys Array of an object
 */
function objectKeys(object: Record<string, string | number>): string[] {
  return Object.keys(object);
}

/**
 * Values of an object
 * @param object Values Array of an object
 * @returns
 */
function objectValues(object: Record<string, string | number>) {
  if (typeof Object.values === "function") return Object.values(object);
  return objectKeys(object).map((k) => object[k]);
}

/**
 * Generates a PHC string using the data provided.
 * @param  opts Object that holds the data needed to generate the PHC
 * string.
 * Detail :
 * @param opts.id Symbolic name for the function.
 * @param opts.version The version of the function.
 * @param opts.params Parameters of the function.
 * @param opts.salt The salt as a binary buffer.
 * @param opts.hash The hash as a binary buffer.
 * @return The hash string adhering to the PHC format.
 */
export function serialize(opts: PhcOptions) {
  const fields = [""];

  if (typeof opts !== "object" || opts === null) {
    throw new TypeError("opts must be an object");
  }

  if (isObjectEmpty(opts)) {
    throw new TypeError("opts is empty");
  }

  // Identifier Validation
  if (typeof opts.id !== "string") {
    throw new TypeError("id must be a string");
  }

  if (!idRegex.test(opts.id)) {
    throw new TypeError(`id must satisfy ${idRegex}`);
  }

  fields.push(opts.id);

  if (typeof opts.version !== "undefined") {
    if (
      typeof opts.version !== "number" ||
      opts.version < 0 ||
      !Number.isInteger(opts.version)
    ) {
      throw new TypeError("version must be a positive integer number");
    }

    fields.push(`v=${opts.version}`);
  }

  // Parameters Validation
  if (opts.params !== undefined) {
    if (typeof opts.params !== "object" || opts.params === null) {
      throw new TypeError("params must be an object");
    }

    const pk = objectKeys(opts.params);
    if (!pk.every((p) => nameRegex.test(p))) {
      throw new TypeError(`params names must satisfy ${nameRegex}`);
    }

    // Convert Numbers into Numeric Strings and Uint8Array into B64 encoded strings.
    pk.forEach((k) => {
      if (opts.params !== undefined) {
        if (typeof opts.params[k] === "number") {
          opts.params[k] = opts.params[k].toString();
        } else if (isUint8Array(opts.params[k])) {
          const val = opts.params[k] as unknown as Uint8Array;
          opts.params[k] = encodeBase64(val);
        }
      }
    });
    const pv = objectValues(opts.params);
    if (!pv.every((v) => typeof v === "string")) {
      throw new TypeError("params values must be strings");
    }

    if (!pv.every((v) => valueRegex.test(v.toString()))) {
      throw new TypeError(`params values must satisfy ${valueRegex}`);
    }

    const strpar = objToKeyVal(opts.params);
    fields.push(strpar);
  }

  if (typeof opts.salt !== "undefined") {
    // Salt Validation
    if (!isUint8Array(opts.salt)) {
      throw new TypeError("salt must be a Uint8Array");
    }

    fields.push(encodeBase64(opts.salt));

    if (typeof opts.hash !== "undefined") {
      // Hash Validation
      if (!isUint8Array(opts.hash)) {
        throw new TypeError("hash must be a Uint8Array");
      }

      fields.push(encodeBase64(opts.hash));
    }
  }

  // Create the PHC formatted string
  const phcstr = fields.join("$");

  return phcstr;
}

/**
 * Parses data from a PHC string.
 * @param  phcstr A PHC string to parse.
 * @return The object containing the data parsed from the PHC string.
 *
 * @example
 *  `$argon2i$v=19$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$iHSDPHzUhPzK7rCcJgOFfg$J4moa2MM0/6uf3HbY2Tf5Fux8JIBTwIhmhxGRbsY14qhTltQt+Vw3b7tcJNEbk8ium8AQfZeD4tabCnNqfkD1g`
 */
export function deserialize(phcstr: string): PhcOptions {
  if (typeof phcstr !== "string" || phcstr === "") {
    throw new TypeError("pchstr must be a non-empty string");
  }

  if (phcstr[0] !== "$") {
    throw new TypeError("pchstr must contain a $ as first char");
  }

  const fields = phcstr.split("$");
  // Remove first empty $
  fields.shift();

  // Parse Fields
  let maxf = 5;
  if (!versionRegex.test(fields[1])) maxf--;
  if (fields.length > maxf) {
    throw new TypeError(
      `pchstr contains too many fields: ${fields.length}/${maxf}`,
    );
  }

  // Parse Identifier
  const id = fields.shift();
  if (id === undefined) {
    throw new TypeError(`no id`);
  }
  if (!idRegex.test(id)) {
    throw new TypeError(`id must satisfy ${idRegex}`);
  }

  let version = -1;
  // Parse Version
  if (versionRegex.test(fields[0])) {
    const field = fields.shift();
    if (field !== undefined) {
      const versionStr = field.match(versionRegex);
      if (versionStr) {
        version = parseInt(versionStr[1], 10);
      }
    }
  }

  let hash;
  let salt;
  if (b64Regex.test(fields[fields.length - 1])) {
    if (fields.length > 1 && b64Regex.test(fields[fields.length - 2])) {
      // Parse Hash
      let field = fields.pop();
      if (field !== undefined) hash = decodeBase64(field);
      // Parse Salt
      field = fields.pop();
      if (field !== undefined) salt = decodeBase64(field);
    } else {
      // Parse Salt
      const field = fields.pop();
      if (field !== undefined) salt = decodeBase64(field);
    }
  }

  // Parse Parameters
  let params: Record<string, string | number> = {};
  if (fields.length > 0) {
    const parstr = fields.pop() || "";
    params = keyValtoObj(parstr);
    if (!objectKeys(params).every((p) => nameRegex.test(p))) {
      throw new TypeError(`params names must satisfy ${nameRegex}`);
    }

    const pv = objectValues(params);
    if (!pv.every((v) => valueRegex.test(v.toString()))) {
      throw new TypeError(`params values must satisfy ${valueRegex}`);
    }

    const pk = objectKeys(params);
    // Convert Decimal Strings into Numbers
    pk.forEach((k) => {
      params[k] = decimalRegex.test(params[k].toString())
        ? parseInt(params[k].toString(), 10)
        : params[k];
    });
  }

  if (fields.length > 0) {
    throw new TypeError(`pchstr contains unrecognized fields: ${fields}`);
  }

  // Build the output object
  const phcobj: Record<string, string | number | Uint8Array | Params> = { id };
  if (version >= 0) phcobj.version = version;
  if (params) phcobj.params = params;
  if (salt) phcobj.salt = salt;
  if (hash) phcobj.hash = hash;

  return phcobj as PhcOptions;
}

/**
 * 	Validates if a value is an Uint8Array.
 *
 * @param value - value to validate
 * @returns boolean indicating if a value is an Uint8Array
 */
function isUint8Array(value: unknown): value is Uint8Array {
  return Object.prototype.toString.call(value) === "[object Uint8Array]";
}

/**
 * Is object empty
 * @param objectName
 * @returns
 */
function isObjectEmpty(
  objectName: object,
): objectName is Record<string, string | number | Uint8Array | Params> {
  return objectName.constructor === Object &&
    Object.keys(objectName).length === 0;
}
