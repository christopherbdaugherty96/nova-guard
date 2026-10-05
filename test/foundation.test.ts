import assert from "node:assert/strict";
import test from "node:test";

import { productName } from "../src/index.js";

test("foundation exports the product name", () => {
  assert.equal(productName, "nova-guard");
});
