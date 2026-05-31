// Import the Registry class that owns CLI construction and command wiring.
import {Registry} from './cli/registry.js'

// Build the Commander program via Registry and hand process.argv to it for parsing.
Registry.build().parse(process.argv)