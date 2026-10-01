import { entropy } from '../src/index.js';
console.table(entropy.compare({ attempts: 5 }));
console.log('TOTP (+/-1 window = 3 valid codes), 6 digits, 5 tries:', entropy.successProbability({ attempts: 5, validCodes: 3 }));
console.log('Digits needed for <=1e-9 success with 5 tries:', entropy.minLengthFor({ attempts: 5, target: 1e-9 }));
