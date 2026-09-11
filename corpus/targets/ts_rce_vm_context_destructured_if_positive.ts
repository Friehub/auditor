// [frensense]
// observation: User-controlled input via destructured body is passed directly to vm.runInContext() for evaluation, enabling arbitrary code execution.
// impact: An attacker can execute arbitrary JavaScript code on the server by including malicious code in the request body.
// improvement: Avoid using vm.runInContext() with user input. Use safe evaluation libraries or parse the input as structured data instead.
// cwe: CWE-94
// cvss: 9.8
// owasp: A03:2021

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
import { eval as safeEval } from 'notevil'

export function b2bOrder() {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (isEnabled()) {
      const orderLinesData = body.orderLinesData || ''
      try {
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ status: 'success' })
      } catch (err) {
        if (err) {
           next(err)
        } else {
           next(err)
        }
      }
    } else {
        res.json({ status: 'success' })
    }
  }
}
