// Проверка умных сводок без запуска Worker: берём функции из src/worker.js.
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

let src = fs.readFileSync('src/worker.js', 'utf8');
src = src.slice(0, src.indexOf('export default {'));
src += '\nmodule.exports={analyzeState,buildSmartMessage};';
const sandbox = {
  console,
  module: { exports: {} },
  Date, Math, Number, String, Object, Array, Set, Map, RegExp, JSON,
  parseInt, parseFloat, isNaN,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(src, sandbox);
const { analyzeState, buildSmartMessage } = sandbox.module.exports;

const now = new Date('2026-11-26T19:00:00Z');

function state(overrides = {}) {
  return Object.assign({
    startCash: 0,
    startCushion: 10000,
    cushionMonths: 3,
    cushionInclude: 'need',
    cushionBase: 'avg',
    windowDays: 30,
    cats: [{ id: 'c1', name: 'Квартира', need: true, archived: false }],
    debts: [],
    savings: [],
    history: [
      { type: 'day', date: '2026-11-26', income: 50000, expenses: { c1: 15000 }, debtPays: {}, savings: {}, savSpend: {}, cushIn: 2000, cushOut: 0 },
      { type: 'day', date: '2026-11-25', income: 0, expenses: { c1: 15000 }, debtPays: {}, savings: {}, savSpend: {}, cushIn: 0, cushOut: 0 },
    ],
  }, overrides);
}

const summary = (s) => buildSmartMessage(s, now, 0, analyzeState(s, now, 0, 2));

let msg = summary(state());
assert(msg.includes('Подушка:'), 'должна быть подушка: ' + msg);
assert(msg.includes('Осталось'), 'должен быть остаток до цели');
assert(msg.includes('👉 Сегодня:'), 'должно быть конкретное действие');
assert(/доход/.test(msg), 'должен быть доход за неделю: ' + msg);
assert(!msg.includes('Долгов нет — подушка и накопления работают на вас.'), 'бесполезная фраза убрана');

msg = summary(state({
  debts: [{ id: 'd1', name: 'Марат', amount: 30000, due: '2026-11-27', archived: false }],
}));
assert(msg.includes('Ближайшие платежи по долгам'), msg);
assert(msg.includes('30 000'), msg);
assert(msg.includes('👉 Сегодня:'), msg);

msg = summary(state({
  savings: [{ id: 'g1', name: 'Ноутбук', archived: false, startFunded: 5000, plan: { amount: 20000, date: '2026-12-20' } }],
}));
assert(msg.includes('🎯 «Ноутбук»'), msg);
assert(msg.includes('15 000'), msg);

msg = summary(state({ cats: [], history: [], startCushion: 0 }));
assert(msg.includes('Данных пока нет'), msg);

console.log('notifications: 4 теста пройдено');
