import test from 'ava'

import { setupProtocol } from '../index'

test('sync function from native code', (t) => {
  t.is(setupProtocol(2 , 5), 10)
})
