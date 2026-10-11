#!/usr/bin/env node
import { main } from "./cli.js";

// The exit code is set, not passed to process.exit(): that can cut off output still waiting in a pipe.
process.exitCode = await main(process.argv.slice(2), process);
