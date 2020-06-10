import { ModuleType } from "./cyrus_type";
import { _setMod } from "./wasm_wrap";

const modFn = require('./cyrus.web.js') as () => Promise<ModuleType>

export const ready = new Promise((resolve) => {
  modFn().then(mod => {
    mod._init()
    _setMod(mod)
    resolve(mod)
  })
})

export {JMAPMailOpts, envelope_to_jmap} from './wasm_wrap'
export {mbox_each, mbox_each_progress, mbox_to_eml} from './mbox_utils'
