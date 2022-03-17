/** @fileOverview Javascript cryptocom implementation.
 *
 * @author Petr Vanek
 */

 "use strict";

cryptocom.parameters.aesAlg = 'AES-GCM';
cryptocom.parameters.aesKeyLen = 256;
cryptocom.parameters.encIVLen = 12;
cryptocom.parameters.hmacAlg = 'SHA-512';
cryptocom.parameters.ecCurveName = 'P-521'; // "P-256", "P-384", "P-521"
cryptocom.parameters.hkdfAlg = 'SHA-512';
cryptocom.parameters.cost_factor_N = 1024;
cryptocom.parameters.block_size_factor_r = 8;
cryptocom.parameters.parallelism_factor = 1;
cryptocom.parameters.salt_size = 128;  //bits
cryptocom.parameters.meta_info =  "MetaKeyPairKeyDerivation";


