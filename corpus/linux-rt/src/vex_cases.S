.intel_syntax noprefix
.text
case_0:
	paddb xmm1, xmm2
	ret
case_1:
	paddb xmm1, [rsi]
	ret
case_2:
	vpaddb xmm1, xmm2, xmm3
	ret
case_3:
	vpaddb xmm1, xmm2, [rsi]
	ret
case_4:
	vpaddb ymm1, ymm2, ymm3
	ret
case_5:
	vpaddb ymm1, ymm2, [rsi]
	ret
case_6:
	paddw xmm1, xmm2
	ret
case_7:
	paddw xmm1, [rsi]
	ret
case_8:
	vpaddw xmm1, xmm2, xmm3
	ret
case_9:
	vpaddw xmm1, xmm2, [rsi]
	ret
case_10:
	vpaddw ymm1, ymm2, ymm3
	ret
case_11:
	vpaddw ymm1, ymm2, [rsi]
	ret
case_12:
	paddd xmm1, xmm2
	ret
case_13:
	paddd xmm1, [rsi]
	ret
case_14:
	vpaddd xmm1, xmm2, xmm3
	ret
case_15:
	vpaddd xmm1, xmm2, [rsi]
	ret
case_16:
	vpaddd ymm1, ymm2, ymm3
	ret
case_17:
	vpaddd ymm1, ymm2, [rsi]
	ret
case_18:
	paddq xmm1, xmm2
	ret
case_19:
	paddq xmm1, [rsi]
	ret
case_20:
	vpaddq xmm1, xmm2, xmm3
	ret
case_21:
	vpaddq xmm1, xmm2, [rsi]
	ret
case_22:
	vpaddq ymm1, ymm2, ymm3
	ret
case_23:
	vpaddq ymm1, ymm2, [rsi]
	ret
case_24:
	psubb xmm1, xmm2
	ret
case_25:
	psubb xmm1, [rsi]
	ret
case_26:
	vpsubb xmm1, xmm2, xmm3
	ret
case_27:
	vpsubb xmm1, xmm2, [rsi]
	ret
case_28:
	vpsubb ymm1, ymm2, ymm3
	ret
case_29:
	vpsubb ymm1, ymm2, [rsi]
	ret
case_30:
	psubw xmm1, xmm2
	ret
case_31:
	psubw xmm1, [rsi]
	ret
case_32:
	vpsubw xmm1, xmm2, xmm3
	ret
case_33:
	vpsubw xmm1, xmm2, [rsi]
	ret
case_34:
	vpsubw ymm1, ymm2, ymm3
	ret
case_35:
	vpsubw ymm1, ymm2, [rsi]
	ret
case_36:
	psubd xmm1, xmm2
	ret
case_37:
	psubd xmm1, [rsi]
	ret
case_38:
	vpsubd xmm1, xmm2, xmm3
	ret
case_39:
	vpsubd xmm1, xmm2, [rsi]
	ret
case_40:
	vpsubd ymm1, ymm2, ymm3
	ret
case_41:
	vpsubd ymm1, ymm2, [rsi]
	ret
case_42:
	psubq xmm1, xmm2
	ret
case_43:
	psubq xmm1, [rsi]
	ret
case_44:
	vpsubq xmm1, xmm2, xmm3
	ret
case_45:
	vpsubq xmm1, xmm2, [rsi]
	ret
case_46:
	vpsubq ymm1, ymm2, ymm3
	ret
case_47:
	vpsubq ymm1, ymm2, [rsi]
	ret
case_48:
	paddsb xmm1, xmm2
	ret
case_49:
	paddsb xmm1, [rsi]
	ret
case_50:
	vpaddsb xmm1, xmm2, xmm3
	ret
case_51:
	vpaddsb xmm1, xmm2, [rsi]
	ret
case_52:
	vpaddsb ymm1, ymm2, ymm3
	ret
case_53:
	vpaddsb ymm1, ymm2, [rsi]
	ret
case_54:
	paddsw xmm1, xmm2
	ret
case_55:
	paddsw xmm1, [rsi]
	ret
case_56:
	vpaddsw xmm1, xmm2, xmm3
	ret
case_57:
	vpaddsw xmm1, xmm2, [rsi]
	ret
case_58:
	vpaddsw ymm1, ymm2, ymm3
	ret
case_59:
	vpaddsw ymm1, ymm2, [rsi]
	ret
case_60:
	paddusb xmm1, xmm2
	ret
case_61:
	paddusb xmm1, [rsi]
	ret
case_62:
	vpaddusb xmm1, xmm2, xmm3
	ret
case_63:
	vpaddusb xmm1, xmm2, [rsi]
	ret
case_64:
	vpaddusb ymm1, ymm2, ymm3
	ret
case_65:
	vpaddusb ymm1, ymm2, [rsi]
	ret
case_66:
	paddusw xmm1, xmm2
	ret
case_67:
	paddusw xmm1, [rsi]
	ret
case_68:
	vpaddusw xmm1, xmm2, xmm3
	ret
case_69:
	vpaddusw xmm1, xmm2, [rsi]
	ret
case_70:
	vpaddusw ymm1, ymm2, ymm3
	ret
case_71:
	vpaddusw ymm1, ymm2, [rsi]
	ret
case_72:
	psubsb xmm1, xmm2
	ret
case_73:
	psubsb xmm1, [rsi]
	ret
case_74:
	vpsubsb xmm1, xmm2, xmm3
	ret
case_75:
	vpsubsb xmm1, xmm2, [rsi]
	ret
case_76:
	vpsubsb ymm1, ymm2, ymm3
	ret
case_77:
	vpsubsb ymm1, ymm2, [rsi]
	ret
case_78:
	psubsw xmm1, xmm2
	ret
case_79:
	psubsw xmm1, [rsi]
	ret
case_80:
	vpsubsw xmm1, xmm2, xmm3
	ret
case_81:
	vpsubsw xmm1, xmm2, [rsi]
	ret
case_82:
	vpsubsw ymm1, ymm2, ymm3
	ret
case_83:
	vpsubsw ymm1, ymm2, [rsi]
	ret
case_84:
	psubusb xmm1, xmm2
	ret
case_85:
	psubusb xmm1, [rsi]
	ret
case_86:
	vpsubusb xmm1, xmm2, xmm3
	ret
case_87:
	vpsubusb xmm1, xmm2, [rsi]
	ret
case_88:
	vpsubusb ymm1, ymm2, ymm3
	ret
case_89:
	vpsubusb ymm1, ymm2, [rsi]
	ret
case_90:
	psubusw xmm1, xmm2
	ret
case_91:
	psubusw xmm1, [rsi]
	ret
case_92:
	vpsubusw xmm1, xmm2, xmm3
	ret
case_93:
	vpsubusw xmm1, xmm2, [rsi]
	ret
case_94:
	vpsubusw ymm1, ymm2, ymm3
	ret
case_95:
	vpsubusw ymm1, ymm2, [rsi]
	ret
case_96:
	pavgb xmm1, xmm2
	ret
case_97:
	pavgb xmm1, [rsi]
	ret
case_98:
	vpavgb xmm1, xmm2, xmm3
	ret
case_99:
	vpavgb xmm1, xmm2, [rsi]
	ret
case_100:
	vpavgb ymm1, ymm2, ymm3
	ret
case_101:
	vpavgb ymm1, ymm2, [rsi]
	ret
case_102:
	pavgw xmm1, xmm2
	ret
case_103:
	pavgw xmm1, [rsi]
	ret
case_104:
	vpavgw xmm1, xmm2, xmm3
	ret
case_105:
	vpavgw xmm1, xmm2, [rsi]
	ret
case_106:
	vpavgw ymm1, ymm2, ymm3
	ret
case_107:
	vpavgw ymm1, ymm2, [rsi]
	ret
case_108:
	pmaxsb xmm1, xmm2
	ret
case_109:
	pmaxsb xmm1, [rsi]
	ret
case_110:
	vpmaxsb xmm1, xmm2, xmm3
	ret
case_111:
	vpmaxsb xmm1, xmm2, [rsi]
	ret
case_112:
	vpmaxsb ymm1, ymm2, ymm3
	ret
case_113:
	vpmaxsb ymm1, ymm2, [rsi]
	ret
case_114:
	pmaxsw xmm1, xmm2
	ret
case_115:
	pmaxsw xmm1, [rsi]
	ret
case_116:
	vpmaxsw xmm1, xmm2, xmm3
	ret
case_117:
	vpmaxsw xmm1, xmm2, [rsi]
	ret
case_118:
	vpmaxsw ymm1, ymm2, ymm3
	ret
case_119:
	vpmaxsw ymm1, ymm2, [rsi]
	ret
case_120:
	pmaxsd xmm1, xmm2
	ret
case_121:
	pmaxsd xmm1, [rsi]
	ret
case_122:
	vpmaxsd xmm1, xmm2, xmm3
	ret
case_123:
	vpmaxsd xmm1, xmm2, [rsi]
	ret
case_124:
	vpmaxsd ymm1, ymm2, ymm3
	ret
case_125:
	vpmaxsd ymm1, ymm2, [rsi]
	ret
case_126:
	pmaxub xmm1, xmm2
	ret
case_127:
	pmaxub xmm1, [rsi]
	ret
case_128:
	vpmaxub xmm1, xmm2, xmm3
	ret
case_129:
	vpmaxub xmm1, xmm2, [rsi]
	ret
case_130:
	vpmaxub ymm1, ymm2, ymm3
	ret
case_131:
	vpmaxub ymm1, ymm2, [rsi]
	ret
case_132:
	pmaxuw xmm1, xmm2
	ret
case_133:
	pmaxuw xmm1, [rsi]
	ret
case_134:
	vpmaxuw xmm1, xmm2, xmm3
	ret
case_135:
	vpmaxuw xmm1, xmm2, [rsi]
	ret
case_136:
	vpmaxuw ymm1, ymm2, ymm3
	ret
case_137:
	vpmaxuw ymm1, ymm2, [rsi]
	ret
case_138:
	pmaxud xmm1, xmm2
	ret
case_139:
	pmaxud xmm1, [rsi]
	ret
case_140:
	vpmaxud xmm1, xmm2, xmm3
	ret
case_141:
	vpmaxud xmm1, xmm2, [rsi]
	ret
case_142:
	vpmaxud ymm1, ymm2, ymm3
	ret
case_143:
	vpmaxud ymm1, ymm2, [rsi]
	ret
case_144:
	pminsb xmm1, xmm2
	ret
case_145:
	pminsb xmm1, [rsi]
	ret
case_146:
	vpminsb xmm1, xmm2, xmm3
	ret
case_147:
	vpminsb xmm1, xmm2, [rsi]
	ret
case_148:
	vpminsb ymm1, ymm2, ymm3
	ret
case_149:
	vpminsb ymm1, ymm2, [rsi]
	ret
case_150:
	pminsw xmm1, xmm2
	ret
case_151:
	pminsw xmm1, [rsi]
	ret
case_152:
	vpminsw xmm1, xmm2, xmm3
	ret
case_153:
	vpminsw xmm1, xmm2, [rsi]
	ret
case_154:
	vpminsw ymm1, ymm2, ymm3
	ret
case_155:
	vpminsw ymm1, ymm2, [rsi]
	ret
case_156:
	pminsd xmm1, xmm2
	ret
case_157:
	pminsd xmm1, [rsi]
	ret
case_158:
	vpminsd xmm1, xmm2, xmm3
	ret
case_159:
	vpminsd xmm1, xmm2, [rsi]
	ret
case_160:
	vpminsd ymm1, ymm2, ymm3
	ret
case_161:
	vpminsd ymm1, ymm2, [rsi]
	ret
case_162:
	pminub xmm1, xmm2
	ret
case_163:
	pminub xmm1, [rsi]
	ret
case_164:
	vpminub xmm1, xmm2, xmm3
	ret
case_165:
	vpminub xmm1, xmm2, [rsi]
	ret
case_166:
	vpminub ymm1, ymm2, ymm3
	ret
case_167:
	vpminub ymm1, ymm2, [rsi]
	ret
case_168:
	pminuw xmm1, xmm2
	ret
case_169:
	pminuw xmm1, [rsi]
	ret
case_170:
	vpminuw xmm1, xmm2, xmm3
	ret
case_171:
	vpminuw xmm1, xmm2, [rsi]
	ret
case_172:
	vpminuw ymm1, ymm2, ymm3
	ret
case_173:
	vpminuw ymm1, ymm2, [rsi]
	ret
case_174:
	pminud xmm1, xmm2
	ret
case_175:
	pminud xmm1, [rsi]
	ret
case_176:
	vpminud xmm1, xmm2, xmm3
	ret
case_177:
	vpminud xmm1, xmm2, [rsi]
	ret
case_178:
	vpminud ymm1, ymm2, ymm3
	ret
case_179:
	vpminud ymm1, ymm2, [rsi]
	ret
case_180:
	pcmpeqb xmm1, xmm2
	ret
case_181:
	pcmpeqb xmm1, [rsi]
	ret
case_182:
	vpcmpeqb xmm1, xmm2, xmm3
	ret
case_183:
	vpcmpeqb xmm1, xmm2, [rsi]
	ret
case_184:
	vpcmpeqb ymm1, ymm2, ymm3
	ret
case_185:
	vpcmpeqb ymm1, ymm2, [rsi]
	ret
case_186:
	pcmpeqw xmm1, xmm2
	ret
case_187:
	pcmpeqw xmm1, [rsi]
	ret
case_188:
	vpcmpeqw xmm1, xmm2, xmm3
	ret
case_189:
	vpcmpeqw xmm1, xmm2, [rsi]
	ret
case_190:
	vpcmpeqw ymm1, ymm2, ymm3
	ret
case_191:
	vpcmpeqw ymm1, ymm2, [rsi]
	ret
case_192:
	pcmpeqd xmm1, xmm2
	ret
case_193:
	pcmpeqd xmm1, [rsi]
	ret
case_194:
	vpcmpeqd xmm1, xmm2, xmm3
	ret
case_195:
	vpcmpeqd xmm1, xmm2, [rsi]
	ret
case_196:
	vpcmpeqd ymm1, ymm2, ymm3
	ret
case_197:
	vpcmpeqd ymm1, ymm2, [rsi]
	ret
case_198:
	pcmpeqq xmm1, xmm2
	ret
case_199:
	pcmpeqq xmm1, [rsi]
	ret
case_200:
	vpcmpeqq xmm1, xmm2, xmm3
	ret
case_201:
	vpcmpeqq xmm1, xmm2, [rsi]
	ret
case_202:
	vpcmpeqq ymm1, ymm2, ymm3
	ret
case_203:
	vpcmpeqq ymm1, ymm2, [rsi]
	ret
case_204:
	pcmpgtb xmm1, xmm2
	ret
case_205:
	pcmpgtb xmm1, [rsi]
	ret
case_206:
	vpcmpgtb xmm1, xmm2, xmm3
	ret
case_207:
	vpcmpgtb xmm1, xmm2, [rsi]
	ret
case_208:
	vpcmpgtb ymm1, ymm2, ymm3
	ret
case_209:
	vpcmpgtb ymm1, ymm2, [rsi]
	ret
case_210:
	pcmpgtw xmm1, xmm2
	ret
case_211:
	pcmpgtw xmm1, [rsi]
	ret
case_212:
	vpcmpgtw xmm1, xmm2, xmm3
	ret
case_213:
	vpcmpgtw xmm1, xmm2, [rsi]
	ret
case_214:
	vpcmpgtw ymm1, ymm2, ymm3
	ret
case_215:
	vpcmpgtw ymm1, ymm2, [rsi]
	ret
case_216:
	pcmpgtd xmm1, xmm2
	ret
case_217:
	pcmpgtd xmm1, [rsi]
	ret
case_218:
	vpcmpgtd xmm1, xmm2, xmm3
	ret
case_219:
	vpcmpgtd xmm1, xmm2, [rsi]
	ret
case_220:
	vpcmpgtd ymm1, ymm2, ymm3
	ret
case_221:
	vpcmpgtd ymm1, ymm2, [rsi]
	ret
case_222:
	pcmpgtq xmm1, xmm2
	ret
case_223:
	pcmpgtq xmm1, [rsi]
	ret
case_224:
	vpcmpgtq xmm1, xmm2, xmm3
	ret
case_225:
	vpcmpgtq xmm1, xmm2, [rsi]
	ret
case_226:
	vpcmpgtq ymm1, ymm2, ymm3
	ret
case_227:
	vpcmpgtq ymm1, ymm2, [rsi]
	ret
case_228:
	pand xmm1, xmm2
	ret
case_229:
	pand xmm1, [rsi]
	ret
case_230:
	vpand xmm1, xmm2, xmm3
	ret
case_231:
	vpand xmm1, xmm2, [rsi]
	ret
case_232:
	vpand ymm1, ymm2, ymm3
	ret
case_233:
	vpand ymm1, ymm2, [rsi]
	ret
case_234:
	pandn xmm1, xmm2
	ret
case_235:
	pandn xmm1, [rsi]
	ret
case_236:
	vpandn xmm1, xmm2, xmm3
	ret
case_237:
	vpandn xmm1, xmm2, [rsi]
	ret
case_238:
	vpandn ymm1, ymm2, ymm3
	ret
case_239:
	vpandn ymm1, ymm2, [rsi]
	ret
case_240:
	por xmm1, xmm2
	ret
case_241:
	por xmm1, [rsi]
	ret
case_242:
	vpor xmm1, xmm2, xmm3
	ret
case_243:
	vpor xmm1, xmm2, [rsi]
	ret
case_244:
	vpor ymm1, ymm2, ymm3
	ret
case_245:
	vpor ymm1, ymm2, [rsi]
	ret
case_246:
	pxor xmm1, xmm2
	ret
case_247:
	pxor xmm1, [rsi]
	ret
case_248:
	vpxor xmm1, xmm2, xmm3
	ret
case_249:
	vpxor xmm1, xmm2, [rsi]
	ret
case_250:
	vpxor ymm1, ymm2, ymm3
	ret
case_251:
	vpxor ymm1, ymm2, [rsi]
	ret
case_252:
	pmullw xmm1, xmm2
	ret
case_253:
	pmullw xmm1, [rsi]
	ret
case_254:
	vpmullw xmm1, xmm2, xmm3
	ret
case_255:
	vpmullw xmm1, xmm2, [rsi]
	ret
case_256:
	vpmullw ymm1, ymm2, ymm3
	ret
case_257:
	vpmullw ymm1, ymm2, [rsi]
	ret
case_258:
	pmulld xmm1, xmm2
	ret
case_259:
	pmulld xmm1, [rsi]
	ret
case_260:
	vpmulld xmm1, xmm2, xmm3
	ret
case_261:
	vpmulld xmm1, xmm2, [rsi]
	ret
case_262:
	vpmulld ymm1, ymm2, ymm3
	ret
case_263:
	vpmulld ymm1, ymm2, [rsi]
	ret
case_264:
	pmulhw xmm1, xmm2
	ret
case_265:
	pmulhw xmm1, [rsi]
	ret
case_266:
	vpmulhw xmm1, xmm2, xmm3
	ret
case_267:
	vpmulhw xmm1, xmm2, [rsi]
	ret
case_268:
	vpmulhw ymm1, ymm2, ymm3
	ret
case_269:
	vpmulhw ymm1, ymm2, [rsi]
	ret
case_270:
	pmulhuw xmm1, xmm2
	ret
case_271:
	pmulhuw xmm1, [rsi]
	ret
case_272:
	vpmulhuw xmm1, xmm2, xmm3
	ret
case_273:
	vpmulhuw xmm1, xmm2, [rsi]
	ret
case_274:
	vpmulhuw ymm1, ymm2, ymm3
	ret
case_275:
	vpmulhuw ymm1, ymm2, [rsi]
	ret
case_276:
	pmulhrsw xmm1, xmm2
	ret
case_277:
	pmulhrsw xmm1, [rsi]
	ret
case_278:
	vpmulhrsw xmm1, xmm2, xmm3
	ret
case_279:
	vpmulhrsw xmm1, xmm2, [rsi]
	ret
case_280:
	vpmulhrsw ymm1, ymm2, ymm3
	ret
case_281:
	vpmulhrsw ymm1, ymm2, [rsi]
	ret
case_282:
	pmuldq xmm1, xmm2
	ret
case_283:
	pmuldq xmm1, [rsi]
	ret
case_284:
	vpmuldq xmm1, xmm2, xmm3
	ret
case_285:
	vpmuldq xmm1, xmm2, [rsi]
	ret
case_286:
	vpmuldq ymm1, ymm2, ymm3
	ret
case_287:
	vpmuldq ymm1, ymm2, [rsi]
	ret
case_288:
	pmuludq xmm1, xmm2
	ret
case_289:
	pmuludq xmm1, [rsi]
	ret
case_290:
	vpmuludq xmm1, xmm2, xmm3
	ret
case_291:
	vpmuludq xmm1, xmm2, [rsi]
	ret
case_292:
	vpmuludq ymm1, ymm2, ymm3
	ret
case_293:
	vpmuludq ymm1, ymm2, [rsi]
	ret
case_294:
	pmaddwd xmm1, xmm2
	ret
case_295:
	pmaddwd xmm1, [rsi]
	ret
case_296:
	vpmaddwd xmm1, xmm2, xmm3
	ret
case_297:
	vpmaddwd xmm1, xmm2, [rsi]
	ret
case_298:
	vpmaddwd ymm1, ymm2, ymm3
	ret
case_299:
	vpmaddwd ymm1, ymm2, [rsi]
	ret
case_300:
	pmaddubsw xmm1, xmm2
	ret
case_301:
	pmaddubsw xmm1, [rsi]
	ret
case_302:
	vpmaddubsw xmm1, xmm2, xmm3
	ret
case_303:
	vpmaddubsw xmm1, xmm2, [rsi]
	ret
case_304:
	vpmaddubsw ymm1, ymm2, ymm3
	ret
case_305:
	vpmaddubsw ymm1, ymm2, [rsi]
	ret
case_306:
	psadbw xmm1, xmm2
	ret
case_307:
	psadbw xmm1, [rsi]
	ret
case_308:
	vpsadbw xmm1, xmm2, xmm3
	ret
case_309:
	vpsadbw xmm1, xmm2, [rsi]
	ret
case_310:
	vpsadbw ymm1, ymm2, ymm3
	ret
case_311:
	vpsadbw ymm1, ymm2, [rsi]
	ret
case_312:
	psignb xmm1, xmm2
	ret
case_313:
	psignb xmm1, [rsi]
	ret
case_314:
	vpsignb xmm1, xmm2, xmm3
	ret
case_315:
	vpsignb xmm1, xmm2, [rsi]
	ret
case_316:
	vpsignb ymm1, ymm2, ymm3
	ret
case_317:
	vpsignb ymm1, ymm2, [rsi]
	ret
case_318:
	psignw xmm1, xmm2
	ret
case_319:
	psignw xmm1, [rsi]
	ret
case_320:
	vpsignw xmm1, xmm2, xmm3
	ret
case_321:
	vpsignw xmm1, xmm2, [rsi]
	ret
case_322:
	vpsignw ymm1, ymm2, ymm3
	ret
case_323:
	vpsignw ymm1, ymm2, [rsi]
	ret
case_324:
	psignd xmm1, xmm2
	ret
case_325:
	psignd xmm1, [rsi]
	ret
case_326:
	vpsignd xmm1, xmm2, xmm3
	ret
case_327:
	vpsignd xmm1, xmm2, [rsi]
	ret
case_328:
	vpsignd ymm1, ymm2, ymm3
	ret
case_329:
	vpsignd ymm1, ymm2, [rsi]
	ret
case_330:
	punpcklbw xmm1, xmm2
	ret
case_331:
	punpcklbw xmm1, [rsi]
	ret
case_332:
	vpunpcklbw xmm1, xmm2, xmm3
	ret
case_333:
	vpunpcklbw xmm1, xmm2, [rsi]
	ret
case_334:
	vpunpcklbw ymm1, ymm2, ymm3
	ret
case_335:
	vpunpcklbw ymm1, ymm2, [rsi]
	ret
case_336:
	punpcklwd xmm1, xmm2
	ret
case_337:
	punpcklwd xmm1, [rsi]
	ret
case_338:
	vpunpcklwd xmm1, xmm2, xmm3
	ret
case_339:
	vpunpcklwd xmm1, xmm2, [rsi]
	ret
case_340:
	vpunpcklwd ymm1, ymm2, ymm3
	ret
case_341:
	vpunpcklwd ymm1, ymm2, [rsi]
	ret
case_342:
	punpckldq xmm1, xmm2
	ret
case_343:
	punpckldq xmm1, [rsi]
	ret
case_344:
	vpunpckldq xmm1, xmm2, xmm3
	ret
case_345:
	vpunpckldq xmm1, xmm2, [rsi]
	ret
case_346:
	vpunpckldq ymm1, ymm2, ymm3
	ret
case_347:
	vpunpckldq ymm1, ymm2, [rsi]
	ret
case_348:
	punpcklqdq xmm1, xmm2
	ret
case_349:
	punpcklqdq xmm1, [rsi]
	ret
case_350:
	vpunpcklqdq xmm1, xmm2, xmm3
	ret
case_351:
	vpunpcklqdq xmm1, xmm2, [rsi]
	ret
case_352:
	vpunpcklqdq ymm1, ymm2, ymm3
	ret
case_353:
	vpunpcklqdq ymm1, ymm2, [rsi]
	ret
case_354:
	punpckhbw xmm1, xmm2
	ret
case_355:
	punpckhbw xmm1, [rsi]
	ret
case_356:
	vpunpckhbw xmm1, xmm2, xmm3
	ret
case_357:
	vpunpckhbw xmm1, xmm2, [rsi]
	ret
case_358:
	vpunpckhbw ymm1, ymm2, ymm3
	ret
case_359:
	vpunpckhbw ymm1, ymm2, [rsi]
	ret
case_360:
	punpckhwd xmm1, xmm2
	ret
case_361:
	punpckhwd xmm1, [rsi]
	ret
case_362:
	vpunpckhwd xmm1, xmm2, xmm3
	ret
case_363:
	vpunpckhwd xmm1, xmm2, [rsi]
	ret
case_364:
	vpunpckhwd ymm1, ymm2, ymm3
	ret
case_365:
	vpunpckhwd ymm1, ymm2, [rsi]
	ret
case_366:
	punpckhdq xmm1, xmm2
	ret
case_367:
	punpckhdq xmm1, [rsi]
	ret
case_368:
	vpunpckhdq xmm1, xmm2, xmm3
	ret
case_369:
	vpunpckhdq xmm1, xmm2, [rsi]
	ret
case_370:
	vpunpckhdq ymm1, ymm2, ymm3
	ret
case_371:
	vpunpckhdq ymm1, ymm2, [rsi]
	ret
case_372:
	punpckhqdq xmm1, xmm2
	ret
case_373:
	punpckhqdq xmm1, [rsi]
	ret
case_374:
	vpunpckhqdq xmm1, xmm2, xmm3
	ret
case_375:
	vpunpckhqdq xmm1, xmm2, [rsi]
	ret
case_376:
	vpunpckhqdq ymm1, ymm2, ymm3
	ret
case_377:
	vpunpckhqdq ymm1, ymm2, [rsi]
	ret
case_378:
	packsswb xmm1, xmm2
	ret
case_379:
	packsswb xmm1, [rsi]
	ret
case_380:
	vpacksswb xmm1, xmm2, xmm3
	ret
case_381:
	vpacksswb xmm1, xmm2, [rsi]
	ret
case_382:
	vpacksswb ymm1, ymm2, ymm3
	ret
case_383:
	vpacksswb ymm1, ymm2, [rsi]
	ret
case_384:
	packuswb xmm1, xmm2
	ret
case_385:
	packuswb xmm1, [rsi]
	ret
case_386:
	vpackuswb xmm1, xmm2, xmm3
	ret
case_387:
	vpackuswb xmm1, xmm2, [rsi]
	ret
case_388:
	vpackuswb ymm1, ymm2, ymm3
	ret
case_389:
	vpackuswb ymm1, ymm2, [rsi]
	ret
case_390:
	packssdw xmm1, xmm2
	ret
case_391:
	packssdw xmm1, [rsi]
	ret
case_392:
	vpackssdw xmm1, xmm2, xmm3
	ret
case_393:
	vpackssdw xmm1, xmm2, [rsi]
	ret
case_394:
	vpackssdw ymm1, ymm2, ymm3
	ret
case_395:
	vpackssdw ymm1, ymm2, [rsi]
	ret
case_396:
	packusdw xmm1, xmm2
	ret
case_397:
	packusdw xmm1, [rsi]
	ret
case_398:
	vpackusdw xmm1, xmm2, xmm3
	ret
case_399:
	vpackusdw xmm1, xmm2, [rsi]
	ret
case_400:
	vpackusdw ymm1, ymm2, ymm3
	ret
case_401:
	vpackusdw ymm1, ymm2, [rsi]
	ret
case_402:
	pshufb xmm1, xmm2
	ret
case_403:
	pshufb xmm1, [rsi]
	ret
case_404:
	vpshufb xmm1, xmm2, xmm3
	ret
case_405:
	vpshufb xmm1, xmm2, [rsi]
	ret
case_406:
	vpshufb ymm1, ymm2, ymm3
	ret
case_407:
	vpshufb ymm1, ymm2, [rsi]
	ret
case_408:
	phaddw xmm1, xmm2
	ret
case_409:
	phaddw xmm1, [rsi]
	ret
case_410:
	vphaddw xmm1, xmm2, xmm3
	ret
case_411:
	vphaddw xmm1, xmm2, [rsi]
	ret
case_412:
	vphaddw ymm1, ymm2, ymm3
	ret
case_413:
	vphaddw ymm1, ymm2, [rsi]
	ret
case_414:
	phaddd xmm1, xmm2
	ret
case_415:
	phaddd xmm1, [rsi]
	ret
case_416:
	vphaddd xmm1, xmm2, xmm3
	ret
case_417:
	vphaddd xmm1, xmm2, [rsi]
	ret
case_418:
	vphaddd ymm1, ymm2, ymm3
	ret
case_419:
	vphaddd ymm1, ymm2, [rsi]
	ret
case_420:
	phaddsw xmm1, xmm2
	ret
case_421:
	phaddsw xmm1, [rsi]
	ret
case_422:
	vphaddsw xmm1, xmm2, xmm3
	ret
case_423:
	vphaddsw xmm1, xmm2, [rsi]
	ret
case_424:
	vphaddsw ymm1, ymm2, ymm3
	ret
case_425:
	vphaddsw ymm1, ymm2, [rsi]
	ret
case_426:
	phsubw xmm1, xmm2
	ret
case_427:
	phsubw xmm1, [rsi]
	ret
case_428:
	vphsubw xmm1, xmm2, xmm3
	ret
case_429:
	vphsubw xmm1, xmm2, [rsi]
	ret
case_430:
	vphsubw ymm1, ymm2, ymm3
	ret
case_431:
	vphsubw ymm1, ymm2, [rsi]
	ret
case_432:
	phsubd xmm1, xmm2
	ret
case_433:
	phsubd xmm1, [rsi]
	ret
case_434:
	vphsubd xmm1, xmm2, xmm3
	ret
case_435:
	vphsubd xmm1, xmm2, [rsi]
	ret
case_436:
	vphsubd ymm1, ymm2, ymm3
	ret
case_437:
	vphsubd ymm1, ymm2, [rsi]
	ret
case_438:
	phsubsw xmm1, xmm2
	ret
case_439:
	phsubsw xmm1, [rsi]
	ret
case_440:
	vphsubsw xmm1, xmm2, xmm3
	ret
case_441:
	vphsubsw xmm1, xmm2, [rsi]
	ret
case_442:
	vphsubsw ymm1, ymm2, ymm3
	ret
case_443:
	vphsubsw ymm1, ymm2, [rsi]
	ret
case_444:
	pabsb xmm1, xmm2
	ret
case_445:
	vpabsb xmm1, xmm2
	ret
case_446:
	vpabsb ymm1, ymm2
	ret
case_447:
	vpabsb ymm1, [rsi]
	ret
case_448:
	pabsw xmm1, xmm2
	ret
case_449:
	vpabsw xmm1, xmm2
	ret
case_450:
	vpabsw ymm1, ymm2
	ret
case_451:
	vpabsw ymm1, [rsi]
	ret
case_452:
	pabsd xmm1, xmm2
	ret
case_453:
	vpabsd xmm1, xmm2
	ret
case_454:
	vpabsd ymm1, ymm2
	ret
case_455:
	vpabsd ymm1, [rsi]
	ret
case_456:
	pmovzxbw xmm1, xmm2
	ret
case_457:
	vpmovzxbw xmm1, xmm2
	ret
case_458:
	vpmovzxbw ymm1, xmm2
	ret
case_459:
	vpmovzxbw ymm1, [rsi]
	ret
case_460:
	pmovzxbd xmm1, xmm2
	ret
case_461:
	vpmovzxbd xmm1, xmm2
	ret
case_462:
	vpmovzxbd ymm1, xmm2
	ret
case_463:
	vpmovzxbd ymm1, [rsi]
	ret
case_464:
	pmovzxbq xmm1, xmm2
	ret
case_465:
	vpmovzxbq xmm1, xmm2
	ret
case_466:
	vpmovzxbq ymm1, xmm2
	ret
case_467:
	vpmovzxbq ymm1, [rsi]
	ret
case_468:
	pmovzxwd xmm1, xmm2
	ret
case_469:
	vpmovzxwd xmm1, xmm2
	ret
case_470:
	vpmovzxwd ymm1, xmm2
	ret
case_471:
	vpmovzxwd ymm1, [rsi]
	ret
case_472:
	pmovzxwq xmm1, xmm2
	ret
case_473:
	vpmovzxwq xmm1, xmm2
	ret
case_474:
	vpmovzxwq ymm1, xmm2
	ret
case_475:
	vpmovzxwq ymm1, [rsi]
	ret
case_476:
	pmovzxdq xmm1, xmm2
	ret
case_477:
	vpmovzxdq xmm1, xmm2
	ret
case_478:
	vpmovzxdq ymm1, xmm2
	ret
case_479:
	vpmovzxdq ymm1, [rsi]
	ret
case_480:
	pmovsxbw xmm1, xmm2
	ret
case_481:
	vpmovsxbw xmm1, xmm2
	ret
case_482:
	vpmovsxbw ymm1, xmm2
	ret
case_483:
	vpmovsxbw ymm1, [rsi]
	ret
case_484:
	pmovsxbd xmm1, xmm2
	ret
case_485:
	vpmovsxbd xmm1, xmm2
	ret
case_486:
	vpmovsxbd ymm1, xmm2
	ret
case_487:
	vpmovsxbd ymm1, [rsi]
	ret
case_488:
	pmovsxbq xmm1, xmm2
	ret
case_489:
	vpmovsxbq xmm1, xmm2
	ret
case_490:
	vpmovsxbq ymm1, xmm2
	ret
case_491:
	vpmovsxbq ymm1, [rsi]
	ret
case_492:
	pmovsxwd xmm1, xmm2
	ret
case_493:
	vpmovsxwd xmm1, xmm2
	ret
case_494:
	vpmovsxwd ymm1, xmm2
	ret
case_495:
	vpmovsxwd ymm1, [rsi]
	ret
case_496:
	pmovsxwq xmm1, xmm2
	ret
case_497:
	vpmovsxwq xmm1, xmm2
	ret
case_498:
	vpmovsxwq ymm1, xmm2
	ret
case_499:
	vpmovsxwq ymm1, [rsi]
	ret
case_500:
	pmovsxdq xmm1, xmm2
	ret
case_501:
	vpmovsxdq xmm1, xmm2
	ret
case_502:
	vpmovsxdq ymm1, xmm2
	ret
case_503:
	vpmovsxdq ymm1, [rsi]
	ret
case_504:
	psllw xmm1, 3
	ret
case_505:
	vpsllw xmm1, xmm2, 3
	ret
case_506:
	vpsllw ymm1, ymm2, 3
	ret
case_507:
	psllw xmm1, 40
	ret
case_508:
	vpsllw xmm1, xmm2, 40
	ret
case_509:
	vpsllw ymm1, ymm2, 40
	ret
case_510:
	psllw xmm1, xmm5
	ret
case_511:
	vpsllw ymm1, ymm2, xmm5
	ret
case_512:
	vpsllw ymm1, ymm2, [rsi]
	ret
case_513:
	pslld xmm1, 3
	ret
case_514:
	vpslld xmm1, xmm2, 3
	ret
case_515:
	vpslld ymm1, ymm2, 3
	ret
case_516:
	pslld xmm1, 40
	ret
case_517:
	vpslld xmm1, xmm2, 40
	ret
case_518:
	vpslld ymm1, ymm2, 40
	ret
case_519:
	pslld xmm1, xmm5
	ret
case_520:
	vpslld ymm1, ymm2, xmm5
	ret
case_521:
	vpslld ymm1, ymm2, [rsi]
	ret
case_522:
	psllq xmm1, 3
	ret
case_523:
	vpsllq xmm1, xmm2, 3
	ret
case_524:
	vpsllq ymm1, ymm2, 3
	ret
case_525:
	psllq xmm1, 40
	ret
case_526:
	vpsllq xmm1, xmm2, 40
	ret
case_527:
	vpsllq ymm1, ymm2, 40
	ret
case_528:
	psllq xmm1, xmm5
	ret
case_529:
	vpsllq ymm1, ymm2, xmm5
	ret
case_530:
	vpsllq ymm1, ymm2, [rsi]
	ret
case_531:
	psrlw xmm1, 3
	ret
case_532:
	vpsrlw xmm1, xmm2, 3
	ret
case_533:
	vpsrlw ymm1, ymm2, 3
	ret
case_534:
	psrlw xmm1, 40
	ret
case_535:
	vpsrlw xmm1, xmm2, 40
	ret
case_536:
	vpsrlw ymm1, ymm2, 40
	ret
case_537:
	psrlw xmm1, xmm5
	ret
case_538:
	vpsrlw ymm1, ymm2, xmm5
	ret
case_539:
	vpsrlw ymm1, ymm2, [rsi]
	ret
case_540:
	psrld xmm1, 3
	ret
case_541:
	vpsrld xmm1, xmm2, 3
	ret
case_542:
	vpsrld ymm1, ymm2, 3
	ret
case_543:
	psrld xmm1, 40
	ret
case_544:
	vpsrld xmm1, xmm2, 40
	ret
case_545:
	vpsrld ymm1, ymm2, 40
	ret
case_546:
	psrld xmm1, xmm5
	ret
case_547:
	vpsrld ymm1, ymm2, xmm5
	ret
case_548:
	vpsrld ymm1, ymm2, [rsi]
	ret
case_549:
	psrlq xmm1, 3
	ret
case_550:
	vpsrlq xmm1, xmm2, 3
	ret
case_551:
	vpsrlq ymm1, ymm2, 3
	ret
case_552:
	psrlq xmm1, 40
	ret
case_553:
	vpsrlq xmm1, xmm2, 40
	ret
case_554:
	vpsrlq ymm1, ymm2, 40
	ret
case_555:
	psrlq xmm1, xmm5
	ret
case_556:
	vpsrlq ymm1, ymm2, xmm5
	ret
case_557:
	vpsrlq ymm1, ymm2, [rsi]
	ret
case_558:
	psraw xmm1, 3
	ret
case_559:
	vpsraw xmm1, xmm2, 3
	ret
case_560:
	vpsraw ymm1, ymm2, 3
	ret
case_561:
	psraw xmm1, 40
	ret
case_562:
	vpsraw xmm1, xmm2, 40
	ret
case_563:
	vpsraw ymm1, ymm2, 40
	ret
case_564:
	psraw xmm1, xmm5
	ret
case_565:
	vpsraw ymm1, ymm2, xmm5
	ret
case_566:
	vpsraw ymm1, ymm2, [rsi]
	ret
case_567:
	psrad xmm1, 3
	ret
case_568:
	vpsrad xmm1, xmm2, 3
	ret
case_569:
	vpsrad ymm1, ymm2, 3
	ret
case_570:
	psrad xmm1, 40
	ret
case_571:
	vpsrad xmm1, xmm2, 40
	ret
case_572:
	vpsrad ymm1, ymm2, 40
	ret
case_573:
	psrad xmm1, xmm5
	ret
case_574:
	vpsrad ymm1, ymm2, xmm5
	ret
case_575:
	vpsrad ymm1, ymm2, [rsi]
	ret
case_576:
	pslldq xmm1, 3
	ret
case_577:
	vpslldq xmm1, xmm2, 3
	ret
case_578:
	vpslldq ymm1, ymm2, 3
	ret
case_579:
	pslldq xmm1, 15
	ret
case_580:
	vpslldq xmm1, xmm2, 15
	ret
case_581:
	vpslldq ymm1, ymm2, 15
	ret
case_582:
	pslldq xmm1, 20
	ret
case_583:
	vpslldq xmm1, xmm2, 20
	ret
case_584:
	vpslldq ymm1, ymm2, 20
	ret
case_585:
	psrldq xmm1, 3
	ret
case_586:
	vpsrldq xmm1, xmm2, 3
	ret
case_587:
	vpsrldq ymm1, ymm2, 3
	ret
case_588:
	psrldq xmm1, 15
	ret
case_589:
	vpsrldq xmm1, xmm2, 15
	ret
case_590:
	vpsrldq ymm1, ymm2, 15
	ret
case_591:
	psrldq xmm1, 20
	ret
case_592:
	vpsrldq xmm1, xmm2, 20
	ret
case_593:
	vpsrldq ymm1, ymm2, 20
	ret
case_594:
	vpsllvd xmm1, xmm2, xmm4
	ret
case_595:
	vpsllvd ymm1, ymm2, ymm4
	ret
case_596:
	vpsllvd ymm1, ymm2, [rsi]
	ret
case_597:
	vpsllvq xmm1, xmm2, xmm4
	ret
case_598:
	vpsllvq ymm1, ymm2, ymm4
	ret
case_599:
	vpsllvq ymm1, ymm2, [rsi]
	ret
case_600:
	vpsrlvd xmm1, xmm2, xmm4
	ret
case_601:
	vpsrlvd ymm1, ymm2, ymm4
	ret
case_602:
	vpsrlvd ymm1, ymm2, [rsi]
	ret
case_603:
	vpsrlvq xmm1, xmm2, xmm4
	ret
case_604:
	vpsrlvq ymm1, ymm2, ymm4
	ret
case_605:
	vpsrlvq ymm1, ymm2, [rsi]
	ret
case_606:
	vpsravd xmm1, xmm2, xmm4
	ret
case_607:
	vpsravd ymm1, ymm2, ymm4
	ret
case_608:
	vpsravd ymm1, ymm2, [rsi]
	ret
case_609:
	pshufd xmm1, xmm2, 0x1b
	ret
case_610:
	vpshufd xmm1, xmm2, 0x1b
	ret
case_611:
	vpshufd ymm1, ymm2, 0x72
	ret
case_612:
	vpshufd ymm1, [rsi], 0x72
	ret
case_613:
	pshuflw xmm1, xmm2, 0x1b
	ret
case_614:
	vpshuflw xmm1, xmm2, 0x1b
	ret
case_615:
	vpshuflw ymm1, ymm2, 0x72
	ret
case_616:
	vpshuflw ymm1, [rsi], 0x72
	ret
case_617:
	pshufhw xmm1, xmm2, 0x1b
	ret
case_618:
	vpshufhw xmm1, xmm2, 0x1b
	ret
case_619:
	vpshufhw ymm1, ymm2, 0x72
	ret
case_620:
	vpshufhw ymm1, [rsi], 0x72
	ret
case_621:
	palignr xmm1, xmm2, 3
	ret
case_622:
	vpalignr xmm1, xmm2, xmm3, 3
	ret
case_623:
	vpalignr ymm1, ymm2, ymm3, 3
	ret
case_624:
	palignr xmm1, xmm2, 17
	ret
case_625:
	vpalignr xmm1, xmm2, xmm3, 17
	ret
case_626:
	vpalignr ymm1, ymm2, ymm3, 17
	ret
case_627:
	palignr xmm1, xmm2, 40
	ret
case_628:
	vpalignr xmm1, xmm2, xmm3, 40
	ret
case_629:
	vpalignr ymm1, ymm2, ymm3, 40
	ret
case_630:
	vpalignr ymm1, ymm2, [rsi], 5
	ret
case_631:
	pblendw xmm1, xmm2, 0xa5
	ret
case_632:
	vpblendw xmm1, xmm2, xmm3, 5
	ret
case_633:
	vpblendw ymm1, ymm2, ymm3, 0xa5
	ret
case_634:
	blendps xmm1, xmm2, 5
	ret
case_635:
	vblendps xmm1, xmm2, xmm3, 5
	ret
case_636:
	vblendps ymm1, ymm2, ymm3, 0xa5
	ret
case_637:
	blendpd xmm1, xmm2, 5
	ret
case_638:
	vblendpd xmm1, xmm2, xmm3, 5
	ret
case_639:
	vblendpd ymm1, ymm2, ymm3, 5
	ret
case_640:
	vpblendd xmm1, xmm2, xmm3, 5
	ret
case_641:
	vpblendd ymm1, ymm2, ymm3, 0xa5
	ret
case_642:
	vpblendd ymm1, ymm2, [rsi], 0x3c
	ret
case_643:
	pblendvb xmm1, xmm2, xmm0
	ret
case_644:
	blendvps xmm1, xmm2, xmm0
	ret
case_645:
	blendvpd xmm1, xmm2, xmm0
	ret
case_646:
	vpblendvb xmm1, xmm2, xmm3, xmm4
	ret
case_647:
	vpblendvb ymm1, ymm2, ymm3, ymm4
	ret
case_648:
	vpblendvb ymm1, ymm2, [rsi], ymm4
	ret
case_649:
	vblendvps xmm1, xmm2, xmm3, xmm4
	ret
case_650:
	vblendvps ymm1, ymm2, ymm3, ymm4
	ret
case_651:
	vblendvps ymm1, ymm2, [rsi], ymm4
	ret
case_652:
	vblendvpd xmm1, xmm2, xmm3, xmm4
	ret
case_653:
	vblendvpd ymm1, ymm2, ymm3, ymm4
	ret
case_654:
	vblendvpd ymm1, ymm2, [rsi], ymm4
	ret
case_655:
	shufps xmm1, xmm2, 0x1b
	ret
case_656:
	vshufps xmm1, xmm2, xmm3, 0x1b
	ret
case_657:
	vshufps ymm1, ymm2, ymm3, 0x72
	ret
case_658:
	shufpd xmm1, xmm2, 0x1b
	ret
case_659:
	vshufpd xmm1, xmm2, xmm3, 0x1b
	ret
case_660:
	vshufpd ymm1, ymm2, ymm3, 0x72
	ret
case_661:
	unpcklps xmm1, xmm2
	ret
case_662:
	vunpcklps xmm1, xmm2, xmm3
	ret
case_663:
	vunpcklps ymm1, ymm2, ymm3
	ret
case_664:
	unpcklpd xmm1, xmm2
	ret
case_665:
	vunpcklpd xmm1, xmm2, xmm3
	ret
case_666:
	vunpcklpd ymm1, ymm2, ymm3
	ret
case_667:
	unpckhps xmm1, xmm2
	ret
case_668:
	vunpckhps xmm1, xmm2, xmm3
	ret
case_669:
	vunpckhps ymm1, ymm2, ymm3
	ret
case_670:
	unpckhpd xmm1, xmm2
	ret
case_671:
	vunpckhpd xmm1, xmm2, xmm3
	ret
case_672:
	vunpckhpd ymm1, ymm2, ymm3
	ret
case_673:
	andps xmm1, xmm2
	ret
case_674:
	vandps xmm1, xmm2, xmm3
	ret
case_675:
	vandps ymm1, ymm2, ymm3
	ret
case_676:
	vandps ymm1, ymm2, [rsi]
	ret
case_677:
	andpd xmm1, xmm2
	ret
case_678:
	vandpd xmm1, xmm2, xmm3
	ret
case_679:
	vandpd ymm1, ymm2, ymm3
	ret
case_680:
	vandpd ymm1, ymm2, [rsi]
	ret
case_681:
	orps xmm1, xmm2
	ret
case_682:
	vorps xmm1, xmm2, xmm3
	ret
case_683:
	vorps ymm1, ymm2, ymm3
	ret
case_684:
	vorps ymm1, ymm2, [rsi]
	ret
case_685:
	orpd xmm1, xmm2
	ret
case_686:
	vorpd xmm1, xmm2, xmm3
	ret
case_687:
	vorpd ymm1, ymm2, ymm3
	ret
case_688:
	vorpd ymm1, ymm2, [rsi]
	ret
case_689:
	xorps xmm1, xmm2
	ret
case_690:
	vxorps xmm1, xmm2, xmm3
	ret
case_691:
	vxorps ymm1, ymm2, ymm3
	ret
case_692:
	vxorps ymm1, ymm2, [rsi]
	ret
case_693:
	xorpd xmm1, xmm2
	ret
case_694:
	vxorpd xmm1, xmm2, xmm3
	ret
case_695:
	vxorpd ymm1, ymm2, ymm3
	ret
case_696:
	vxorpd ymm1, ymm2, [rsi]
	ret
case_697:
	andnps xmm1, xmm2
	ret
case_698:
	vandnps xmm1, xmm2, xmm3
	ret
case_699:
	vandnps ymm1, ymm2, ymm3
	ret
case_700:
	vandnps ymm1, ymm2, [rsi]
	ret
case_701:
	andnpd xmm1, xmm2
	ret
case_702:
	vandnpd xmm1, xmm2, xmm3
	ret
case_703:
	vandnpd ymm1, ymm2, ymm3
	ret
case_704:
	vandnpd ymm1, ymm2, [rsi]
	ret
case_705:
	vpermq ymm1, ymm2, 0x1b
	ret
case_706:
	vpermq ymm1, [rsi], 0x72
	ret
case_707:
	vpermpd ymm1, ymm2, 0x1b
	ret
case_708:
	vpermd ymm1, ymm2, ymm3
	ret
case_709:
	vpermd ymm1, ymm2, [rsi]
	ret
case_710:
	vpermps ymm1, ymm2, ymm3
	ret
case_711:
	vperm2i128 ymm1, ymm2, ymm3, 0x21
	ret
case_712:
	vperm2i128 ymm1, ymm2, ymm3, 0x08
	ret
case_713:
	vperm2i128 ymm1, ymm2, [rsi], 0x31
	ret
case_714:
	vperm2f128 ymm1, ymm2, ymm3, 0x12
	ret
case_715:
	vpermilps xmm1, xmm2, 0x1b
	ret
case_716:
	vpermilps ymm1, ymm2, 0x72
	ret
case_717:
	vpermilps ymm1, ymm2, ymm3
	ret
case_718:
	vpermilpd xmm1, xmm2, 1
	ret
case_719:
	vpermilpd ymm1, ymm2, 5
	ret
case_720:
	vpermilpd ymm1, ymm2, ymm3
	ret
case_721:
	vinserti128 ymm1, ymm2, xmm3, 1
	ret
case_722:
	vinserti128 ymm1, ymm2, xmm3, 0
	ret
case_723:
	vinserti128 ymm1, ymm2, [rsi], 1
	ret
case_724:
	vinsertf128 ymm1, ymm2, xmm3, 1
	ret
case_725:
	vinsertf128 ymm1, ymm2, [rsi], 0
	ret
case_726:
	vextracti128 xmm1, ymm2, 1
	ret
case_727:
	vextracti128 xmm1, ymm2, 0
	ret
case_728:
	vextracti128 [rdi], ymm2, 1
	ret
case_729:
	vextractf128 xmm1, ymm2, 1
	ret
case_730:
	vextractf128 [rdi], ymm2, 1
	ret
case_731:
	vpbroadcastb xmm1, xmm2
	ret
case_732:
	vpbroadcastb ymm1, xmm2
	ret
case_733:
	vpbroadcastb ymm1, byte ptr [rsi]
	ret
case_734:
	vpbroadcastw xmm1, xmm2
	ret
case_735:
	vpbroadcastw ymm1, xmm2
	ret
case_736:
	vpbroadcastw ymm1, word ptr [rsi]
	ret
case_737:
	vpbroadcastd xmm1, xmm2
	ret
case_738:
	vpbroadcastd ymm1, xmm2
	ret
case_739:
	vpbroadcastd ymm1, dword ptr [rsi]
	ret
case_740:
	vpbroadcastq xmm1, xmm2
	ret
case_741:
	vpbroadcastq ymm1, xmm2
	ret
case_742:
	vpbroadcastq ymm1, qword ptr [rsi]
	ret
case_743:
	vbroadcastss xmm1, xmm2
	ret
case_744:
	vbroadcastss ymm1, xmm2
	ret
case_745:
	vbroadcastss ymm1, dword ptr [rsi]
	ret
case_746:
	vbroadcastsd ymm1, xmm2
	ret
case_747:
	vbroadcastsd ymm1, qword ptr [rsi]
	ret
case_748:
	vbroadcastf128 ymm1, [rsi]
	ret
case_749:
	vbroadcasti128 ymm1, [rsi]
	ret
case_750:
	ptest xmm1, xmm2
	ret
case_751:
	vptest xmm1, xmm2
	ret
case_752:
	vptest ymm1, ymm2
	ret
case_753:
	vptest ymm0, ymm0
	ret
case_754:
	vptest ymm1, [rsi]
	ret
case_755:
	vtestps xmm1, xmm2
	ret
case_756:
	vtestps ymm1, ymm2
	ret
case_757:
	vtestpd ymm1, ymm2
	ret
case_758:
	pmovmskb eax, xmm2
	ret
case_759:
	vpmovmskb eax, xmm2
	ret
case_760:
	vpmovmskb eax, ymm2
	ret
case_761:
	movmskps eax, xmm2
	ret
case_762:
	vmovmskps eax, xmm2
	ret
case_763:
	vmovmskps eax, ymm2
	ret
case_764:
	movmskpd eax, xmm2
	ret
case_765:
	vmovmskpd eax, ymm2
	ret
case_766:
	vmovd xmm1, eax
	ret
case_767:
	vmovd xmm1, dword ptr [rsi]
	ret
case_768:
	vmovd eax, xmm2
	ret
case_769:
	vmovd dword ptr [rdi], xmm2
	ret
case_770:
	vmovq xmm1, rax
	ret
case_771:
	vmovq xmm1, qword ptr [rsi]
	ret
case_772:
	vmovq rax, xmm2
	ret
case_773:
	vmovq qword ptr [rdi], xmm2
	ret
case_774:
	vmovq xmm1, xmm2
	ret
case_775:
	vmovdqa xmm1, xmm2
	ret
case_776:
	vmovdqa ymm1, ymm2
	ret
case_777:
	vmovdqa ymm1, [rsi]
	ret
case_778:
	vmovdqa [rdi], ymm2
	ret
case_779:
	vmovdqu xmm1, [rsi+1]
	ret
case_780:
	vmovdqu ymm1, [rsi+1]
	ret
case_781:
	vmovdqu [rdi+1], ymm2
	ret
case_782:
	vmovdqu [rdi+1], xmm2
	ret
case_783:
	vmovaps ymm1, ymm2
	ret
case_784:
	vmovaps ymm1, [rsi]
	ret
case_785:
	vmovaps [rdi], ymm2
	ret
case_786:
	vmovups ymm1, [rsi+1]
	ret
case_787:
	vmovups [rdi+1], ymm2
	ret
case_788:
	vmovups xmm1, [rsi+1]
	ret
case_789:
	vmovapd ymm1, [rsi]
	ret
case_790:
	vmovupd ymm1, [rsi+1]
	ret
case_791:
	vmovss xmm1, xmm2, xmm3
	ret
case_792:
	vmovss xmm1, dword ptr [rsi]
	ret
case_793:
	vmovss dword ptr [rdi], xmm2
	ret
case_794:
	vmovsd xmm1, xmm2, xmm3
	ret
case_795:
	vmovsd xmm1, qword ptr [rsi]
	ret
case_796:
	vmovsd qword ptr [rdi], xmm2
	ret
case_797:
	vmovhps xmm1, xmm2, qword ptr [rsi]
	ret
case_798:
	vmovhps qword ptr [rdi], xmm2
	ret
case_799:
	vmovlps xmm1, xmm2, qword ptr [rsi]
	ret
case_800:
	vmovlps qword ptr [rdi], xmm2
	ret
case_801:
	vmovhpd xmm1, xmm2, qword ptr [rsi]
	ret
case_802:
	vmovhpd qword ptr [rdi], xmm2
	ret
case_803:
	vmovlpd xmm1, xmm2, qword ptr [rsi]
	ret
case_804:
	vmovlpd qword ptr [rdi], xmm2
	ret
case_805:
	vmovhlps xmm1, xmm2, xmm3
	ret
case_806:
	vmovlhps xmm1, xmm2, xmm3
	ret
case_807:
	vmovntdq [rdi], ymm2
	ret
case_808:
	vmovntdq [rdi], xmm2
	ret
case_809:
	vmovntdqa ymm1, [rsi]
	ret
case_810:
	vmovntdqa xmm1, [rsi]
	ret
case_811:
	vmovntps [rdi], ymm2
	ret
case_812:
	vmovntpd [rdi], ymm2
	ret
case_813:
	vlddqu ymm1, [rsi+1]
	ret
case_814:
	vlddqu xmm1, [rsi+1]
	ret
case_815:
	vmovshdup ymm1, ymm2
	ret
case_816:
	vmovshdup xmm1, xmm2
	ret
case_817:
	vmovsldup ymm1, ymm2
	ret
case_818:
	vmovsldup xmm1, xmm2
	ret
case_819:
	vmovddup ymm1, ymm2
	ret
case_820:
	vmovddup xmm1, xmm2
	ret
case_821:
	movshdup xmm1, xmm2
	ret
case_822:
	movsldup xmm1, xmm2
	ret
case_823:
	movddup xmm1, xmm2
	ret
case_824:
	lddqu xmm1, [rsi+1]
	ret
case_825:
	movntdqa xmm1, [rsi]
	ret
case_826:
	vpinsrb xmm1, xmm2, eax, 5
	ret
case_827:
	vpinsrw xmm1, xmm2, eax, 5
	ret
case_828:
	vpinsrd xmm1, xmm2, eax, 2
	ret
case_829:
	vpinsrq xmm1, xmm2, rax, 1
	ret
case_830:
	vpinsrb xmm1, xmm2, byte ptr [rsi], 15
	ret
case_831:
	vpinsrw xmm1, xmm2, word ptr [rsi], 7
	ret
case_832:
	vpinsrd xmm1, xmm2, dword ptr [rsi], 3
	ret
case_833:
	vpinsrq xmm1, xmm2, qword ptr [rsi], 0
	ret
case_834:
	vpextrb eax, xmm2, 5
	ret
case_835:
	vpextrw eax, xmm2, 5
	ret
case_836:
	vpextrd eax, xmm2, 2
	ret
case_837:
	vpextrq rax, xmm2, 1
	ret
case_838:
	vpextrb byte ptr [rdi], xmm2, 15
	ret
case_839:
	vpextrw word ptr [rdi], xmm2, 7
	ret
case_840:
	vpextrd dword ptr [rdi], xmm2, 3
	ret
case_841:
	vpextrq qword ptr [rdi], xmm2, 0
	ret
case_842:
	vextractps eax, xmm2, 2
	ret
case_843:
	vextractps dword ptr [rdi], xmm2, 1
	ret
case_844:
	vinsertps xmm1, xmm2, xmm3, 0x9c
	ret
case_845:
	vinsertps xmm1, xmm2, dword ptr [rsi], 0x13
	ret
case_846:
	pinsrb xmm1, eax, 5
	ret
case_847:
	pinsrd xmm1, eax, 2
	ret
case_848:
	pinsrq xmm1, rax, 1
	ret
case_849:
	pinsrw xmm1, eax, 5
	ret
case_850:
	pextrb eax, xmm2, 5
	ret
case_851:
	pextrd eax, xmm2, 2
	ret
case_852:
	pextrq rax, xmm2, 1
	ret
case_853:
	pextrw eax, xmm2, 5
	ret
case_854:
	insertps xmm1, xmm2, 0x9c
	ret
case_855:
	extractps eax, xmm2, 2
	ret
case_856:
	vmaskmovps ymm1, ymm2, [rsi]
	ret
case_857:
	vmaskmovps xmm1, xmm2, [rsi]
	ret
case_858:
	vmaskmovpd ymm1, ymm4, [rsi]
	ret
case_859:
	vmaskmovps [rdi], ymm2, ymm3
	ret
case_860:
	vmaskmovpd [rdi], ymm4, ymm3
	ret
case_861:
	vpmaskmovd ymm1, ymm2, [rsi]
	ret
case_862:
	vpmaskmovd xmm1, xmm2, [rsi]
	ret
case_863:
	vpmaskmovq ymm1, ymm4, [rsi]
	ret
case_864:
	vpmaskmovq xmm1, xmm4, [rsi]
	ret
case_865:
	vpmaskmovd [rdi], ymm2, ymm3
	ret
case_866:
	vpmaskmovq [rdi], ymm4, ymm3
	ret
case_867:
	vpmaskmovd [rdi], xmm2, xmm3
	ret
case_868:
	vzeroupper
	ret
case_869:
	vzeroall
	ret
case_870:
	addps xmm9, xmm10
	ret
case_871:
	vaddps xmm1, xmm9, xmm10
	ret
case_872:
	vaddps ymm1, ymm9, ymm10
	ret
case_873:
	vaddps ymm1, ymm9, [rsi+0]
	ret
case_874:
	addpd xmm13, xmm14
	ret
case_875:
	vaddpd xmm1, xmm13, xmm14
	ret
case_876:
	vaddpd ymm1, ymm13, ymm14
	ret
case_877:
	addss xmm9, xmm10
	ret
case_878:
	vaddss xmm1, xmm9, xmm10
	ret
case_879:
	addsd xmm13, xmm14
	ret
case_880:
	vaddsd xmm1, xmm13, xmm14
	ret
case_881:
	subps xmm9, xmm10
	ret
case_882:
	vsubps xmm1, xmm9, xmm10
	ret
case_883:
	vsubps ymm1, ymm9, ymm10
	ret
case_884:
	vsubps ymm1, ymm9, [rsi+0]
	ret
case_885:
	subpd xmm13, xmm14
	ret
case_886:
	vsubpd xmm1, xmm13, xmm14
	ret
case_887:
	vsubpd ymm1, ymm13, ymm14
	ret
case_888:
	subss xmm9, xmm10
	ret
case_889:
	vsubss xmm1, xmm9, xmm10
	ret
case_890:
	subsd xmm13, xmm14
	ret
case_891:
	vsubsd xmm1, xmm13, xmm14
	ret
case_892:
	mulps xmm9, xmm10
	ret
case_893:
	vmulps xmm1, xmm9, xmm10
	ret
case_894:
	vmulps ymm1, ymm9, ymm10
	ret
case_895:
	vmulps ymm1, ymm9, [rsi+0]
	ret
case_896:
	mulpd xmm13, xmm14
	ret
case_897:
	vmulpd xmm1, xmm13, xmm14
	ret
case_898:
	vmulpd ymm1, ymm13, ymm14
	ret
case_899:
	mulss xmm9, xmm10
	ret
case_900:
	vmulss xmm1, xmm9, xmm10
	ret
case_901:
	mulsd xmm13, xmm14
	ret
case_902:
	vmulsd xmm1, xmm13, xmm14
	ret
case_903:
	divps xmm9, xmm10
	ret
case_904:
	vdivps xmm1, xmm9, xmm10
	ret
case_905:
	vdivps ymm1, ymm9, ymm10
	ret
case_906:
	vdivps ymm1, ymm9, [rsi+0]
	ret
case_907:
	divpd xmm13, xmm14
	ret
case_908:
	vdivpd xmm1, xmm13, xmm14
	ret
case_909:
	vdivpd ymm1, ymm13, ymm14
	ret
case_910:
	divss xmm9, xmm10
	ret
case_911:
	vdivss xmm1, xmm9, xmm10
	ret
case_912:
	divsd xmm13, xmm14
	ret
case_913:
	vdivsd xmm1, xmm13, xmm14
	ret
case_914:
	minps xmm9, xmm10
	ret
case_915:
	vminps xmm1, xmm9, xmm10
	ret
case_916:
	vminps ymm1, ymm9, ymm10
	ret
case_917:
	vminps ymm1, ymm9, [rsi+0]
	ret
case_918:
	minpd xmm13, xmm14
	ret
case_919:
	vminpd xmm1, xmm13, xmm14
	ret
case_920:
	vminpd ymm1, ymm13, ymm14
	ret
case_921:
	minss xmm9, xmm10
	ret
case_922:
	vminss xmm1, xmm9, xmm10
	ret
case_923:
	minsd xmm13, xmm14
	ret
case_924:
	vminsd xmm1, xmm13, xmm14
	ret
case_925:
	maxps xmm9, xmm10
	ret
case_926:
	vmaxps xmm1, xmm9, xmm10
	ret
case_927:
	vmaxps ymm1, ymm9, ymm10
	ret
case_928:
	vmaxps ymm1, ymm9, [rsi+0]
	ret
case_929:
	maxpd xmm13, xmm14
	ret
case_930:
	vmaxpd xmm1, xmm13, xmm14
	ret
case_931:
	vmaxpd ymm1, ymm13, ymm14
	ret
case_932:
	maxss xmm9, xmm10
	ret
case_933:
	vmaxss xmm1, xmm9, xmm10
	ret
case_934:
	maxsd xmm13, xmm14
	ret
case_935:
	vmaxsd xmm1, xmm13, xmm14
	ret
case_936:
	addsubps xmm9, xmm10
	ret
case_937:
	vaddsubps xmm1, xmm9, xmm10
	ret
case_938:
	vaddsubps ymm1, ymm9, ymm10
	ret
case_939:
	vaddsubps ymm1, ymm9, [rsi+0]
	ret
case_940:
	haddps xmm9, xmm10
	ret
case_941:
	vhaddps xmm1, xmm9, xmm10
	ret
case_942:
	vhaddps ymm1, ymm9, ymm10
	ret
case_943:
	vhaddps ymm1, ymm9, [rsi+0]
	ret
case_944:
	hsubps xmm9, xmm10
	ret
case_945:
	vhsubps xmm1, xmm9, xmm10
	ret
case_946:
	vhsubps ymm1, ymm9, ymm10
	ret
case_947:
	vhsubps ymm1, ymm9, [rsi+0]
	ret
case_948:
	addsubpd xmm13, xmm14
	ret
case_949:
	vaddsubpd xmm1, xmm13, xmm14
	ret
case_950:
	vaddsubpd ymm1, ymm13, ymm14
	ret
case_951:
	haddpd xmm13, xmm14
	ret
case_952:
	vhaddpd xmm1, xmm13, xmm14
	ret
case_953:
	vhaddpd ymm1, ymm13, ymm14
	ret
case_954:
	hsubpd xmm13, xmm14
	ret
case_955:
	vhsubpd xmm1, xmm13, xmm14
	ret
case_956:
	vhsubpd ymm1, ymm13, ymm14
	ret
case_957:
	sqrtps xmm1, xmm9
	ret
case_958:
	vsqrtps xmm1, xmm9
	ret
case_959:
	vsqrtps ymm1, ymm9
	ret
case_960:
	vsqrtpd xmm1, xmm13
	ret
case_961:
	vsqrtpd ymm1, ymm13
	ret
case_962:
	vsqrtss xmm1, xmm2, xmm9
	ret
case_963:
	vsqrtsd xmm1, xmm2, xmm13
	ret
case_964:
	vcmpps ymm1, ymm9, ymm10, 0
	ret
case_965:
	vcmppd ymm1, ymm13, ymm14, 0
	ret
case_966:
	vcmpss xmm1, xmm9, xmm11, 0
	ret
case_967:
	vcmpsd xmm1, xmm13, xmm15, 0
	ret
case_968:
	vcmpps ymm1, ymm9, ymm10, 1
	ret
case_969:
	vcmppd ymm1, ymm13, ymm14, 1
	ret
case_970:
	vcmpss xmm1, xmm9, xmm11, 1
	ret
case_971:
	vcmpsd xmm1, xmm13, xmm15, 1
	ret
case_972:
	vcmpps ymm1, ymm9, ymm10, 2
	ret
case_973:
	vcmppd ymm1, ymm13, ymm14, 2
	ret
case_974:
	vcmpss xmm1, xmm9, xmm11, 2
	ret
case_975:
	vcmpsd xmm1, xmm13, xmm15, 2
	ret
case_976:
	vcmpps ymm1, ymm9, ymm10, 3
	ret
case_977:
	vcmppd ymm1, ymm13, ymm14, 3
	ret
case_978:
	vcmpss xmm1, xmm9, xmm11, 3
	ret
case_979:
	vcmpsd xmm1, xmm13, xmm15, 3
	ret
case_980:
	vcmpps ymm1, ymm9, ymm10, 4
	ret
case_981:
	vcmppd ymm1, ymm13, ymm14, 4
	ret
case_982:
	vcmpss xmm1, xmm9, xmm11, 4
	ret
case_983:
	vcmpsd xmm1, xmm13, xmm15, 4
	ret
case_984:
	vcmpps ymm1, ymm9, ymm10, 5
	ret
case_985:
	vcmppd ymm1, ymm13, ymm14, 5
	ret
case_986:
	vcmpss xmm1, xmm9, xmm11, 5
	ret
case_987:
	vcmpsd xmm1, xmm13, xmm15, 5
	ret
case_988:
	vcmpps ymm1, ymm9, ymm10, 6
	ret
case_989:
	vcmppd ymm1, ymm13, ymm14, 6
	ret
case_990:
	vcmpss xmm1, xmm9, xmm11, 6
	ret
case_991:
	vcmpsd xmm1, xmm13, xmm15, 6
	ret
case_992:
	vcmpps ymm1, ymm9, ymm10, 7
	ret
case_993:
	vcmppd ymm1, ymm13, ymm14, 7
	ret
case_994:
	vcmpss xmm1, xmm9, xmm11, 7
	ret
case_995:
	vcmpsd xmm1, xmm13, xmm15, 7
	ret
case_996:
	vcmpps ymm1, ymm9, ymm10, 8
	ret
case_997:
	vcmppd ymm1, ymm13, ymm14, 8
	ret
case_998:
	vcmpss xmm1, xmm9, xmm11, 8
	ret
case_999:
	vcmpsd xmm1, xmm13, xmm15, 8
	ret
case_1000:
	vcmpps ymm1, ymm9, ymm10, 9
	ret
case_1001:
	vcmppd ymm1, ymm13, ymm14, 9
	ret
case_1002:
	vcmpss xmm1, xmm9, xmm11, 9
	ret
case_1003:
	vcmpsd xmm1, xmm13, xmm15, 9
	ret
case_1004:
	vcmpps ymm1, ymm9, ymm10, 10
	ret
case_1005:
	vcmppd ymm1, ymm13, ymm14, 10
	ret
case_1006:
	vcmpss xmm1, xmm9, xmm11, 10
	ret
case_1007:
	vcmpsd xmm1, xmm13, xmm15, 10
	ret
case_1008:
	vcmpps ymm1, ymm9, ymm10, 11
	ret
case_1009:
	vcmppd ymm1, ymm13, ymm14, 11
	ret
case_1010:
	vcmpss xmm1, xmm9, xmm11, 11
	ret
case_1011:
	vcmpsd xmm1, xmm13, xmm15, 11
	ret
case_1012:
	vcmpps ymm1, ymm9, ymm10, 12
	ret
case_1013:
	vcmppd ymm1, ymm13, ymm14, 12
	ret
case_1014:
	vcmpss xmm1, xmm9, xmm11, 12
	ret
case_1015:
	vcmpsd xmm1, xmm13, xmm15, 12
	ret
case_1016:
	vcmpps ymm1, ymm9, ymm10, 13
	ret
case_1017:
	vcmppd ymm1, ymm13, ymm14, 13
	ret
case_1018:
	vcmpss xmm1, xmm9, xmm11, 13
	ret
case_1019:
	vcmpsd xmm1, xmm13, xmm15, 13
	ret
case_1020:
	vcmpps ymm1, ymm9, ymm10, 14
	ret
case_1021:
	vcmppd ymm1, ymm13, ymm14, 14
	ret
case_1022:
	vcmpss xmm1, xmm9, xmm11, 14
	ret
case_1023:
	vcmpsd xmm1, xmm13, xmm15, 14
	ret
case_1024:
	vcmpps ymm1, ymm9, ymm10, 15
	ret
case_1025:
	vcmppd ymm1, ymm13, ymm14, 15
	ret
case_1026:
	vcmpss xmm1, xmm9, xmm11, 15
	ret
case_1027:
	vcmpsd xmm1, xmm13, xmm15, 15
	ret
case_1028:
	vcmpps ymm1, ymm9, ymm10, 16
	ret
case_1029:
	vcmppd ymm1, ymm13, ymm14, 16
	ret
case_1030:
	vcmpss xmm1, xmm9, xmm11, 16
	ret
case_1031:
	vcmpsd xmm1, xmm13, xmm15, 16
	ret
case_1032:
	vcmpps ymm1, ymm9, ymm10, 17
	ret
case_1033:
	vcmppd ymm1, ymm13, ymm14, 17
	ret
case_1034:
	vcmpss xmm1, xmm9, xmm11, 17
	ret
case_1035:
	vcmpsd xmm1, xmm13, xmm15, 17
	ret
case_1036:
	vcmpps ymm1, ymm9, ymm10, 18
	ret
case_1037:
	vcmppd ymm1, ymm13, ymm14, 18
	ret
case_1038:
	vcmpss xmm1, xmm9, xmm11, 18
	ret
case_1039:
	vcmpsd xmm1, xmm13, xmm15, 18
	ret
case_1040:
	vcmpps ymm1, ymm9, ymm10, 19
	ret
case_1041:
	vcmppd ymm1, ymm13, ymm14, 19
	ret
case_1042:
	vcmpss xmm1, xmm9, xmm11, 19
	ret
case_1043:
	vcmpsd xmm1, xmm13, xmm15, 19
	ret
case_1044:
	vcmpps ymm1, ymm9, ymm10, 20
	ret
case_1045:
	vcmppd ymm1, ymm13, ymm14, 20
	ret
case_1046:
	vcmpss xmm1, xmm9, xmm11, 20
	ret
case_1047:
	vcmpsd xmm1, xmm13, xmm15, 20
	ret
case_1048:
	vcmpps ymm1, ymm9, ymm10, 21
	ret
case_1049:
	vcmppd ymm1, ymm13, ymm14, 21
	ret
case_1050:
	vcmpss xmm1, xmm9, xmm11, 21
	ret
case_1051:
	vcmpsd xmm1, xmm13, xmm15, 21
	ret
case_1052:
	vcmpps ymm1, ymm9, ymm10, 22
	ret
case_1053:
	vcmppd ymm1, ymm13, ymm14, 22
	ret
case_1054:
	vcmpss xmm1, xmm9, xmm11, 22
	ret
case_1055:
	vcmpsd xmm1, xmm13, xmm15, 22
	ret
case_1056:
	vcmpps ymm1, ymm9, ymm10, 23
	ret
case_1057:
	vcmppd ymm1, ymm13, ymm14, 23
	ret
case_1058:
	vcmpss xmm1, xmm9, xmm11, 23
	ret
case_1059:
	vcmpsd xmm1, xmm13, xmm15, 23
	ret
case_1060:
	vcmpps ymm1, ymm9, ymm10, 24
	ret
case_1061:
	vcmppd ymm1, ymm13, ymm14, 24
	ret
case_1062:
	vcmpss xmm1, xmm9, xmm11, 24
	ret
case_1063:
	vcmpsd xmm1, xmm13, xmm15, 24
	ret
case_1064:
	vcmpps ymm1, ymm9, ymm10, 25
	ret
case_1065:
	vcmppd ymm1, ymm13, ymm14, 25
	ret
case_1066:
	vcmpss xmm1, xmm9, xmm11, 25
	ret
case_1067:
	vcmpsd xmm1, xmm13, xmm15, 25
	ret
case_1068:
	vcmpps ymm1, ymm9, ymm10, 26
	ret
case_1069:
	vcmppd ymm1, ymm13, ymm14, 26
	ret
case_1070:
	vcmpss xmm1, xmm9, xmm11, 26
	ret
case_1071:
	vcmpsd xmm1, xmm13, xmm15, 26
	ret
case_1072:
	vcmpps ymm1, ymm9, ymm10, 27
	ret
case_1073:
	vcmppd ymm1, ymm13, ymm14, 27
	ret
case_1074:
	vcmpss xmm1, xmm9, xmm11, 27
	ret
case_1075:
	vcmpsd xmm1, xmm13, xmm15, 27
	ret
case_1076:
	vcmpps ymm1, ymm9, ymm10, 28
	ret
case_1077:
	vcmppd ymm1, ymm13, ymm14, 28
	ret
case_1078:
	vcmpss xmm1, xmm9, xmm11, 28
	ret
case_1079:
	vcmpsd xmm1, xmm13, xmm15, 28
	ret
case_1080:
	vcmpps ymm1, ymm9, ymm10, 29
	ret
case_1081:
	vcmppd ymm1, ymm13, ymm14, 29
	ret
case_1082:
	vcmpss xmm1, xmm9, xmm11, 29
	ret
case_1083:
	vcmpsd xmm1, xmm13, xmm15, 29
	ret
case_1084:
	vcmpps ymm1, ymm9, ymm10, 30
	ret
case_1085:
	vcmppd ymm1, ymm13, ymm14, 30
	ret
case_1086:
	vcmpss xmm1, xmm9, xmm11, 30
	ret
case_1087:
	vcmpsd xmm1, xmm13, xmm15, 30
	ret
case_1088:
	vcmpps ymm1, ymm9, ymm10, 31
	ret
case_1089:
	vcmppd ymm1, ymm13, ymm14, 31
	ret
case_1090:
	vcmpss xmm1, xmm9, xmm11, 31
	ret
case_1091:
	vcmpsd xmm1, xmm13, xmm15, 31
	ret
case_1092:
	vcmpps xmm1, xmm9, xmm10, 1
	ret
case_1093:
	vcmppd xmm1, xmm13, xmm14, 2
	ret
case_1094:
	cmpps xmm9, xmm10, 1
	ret
case_1095:
	cmpsd xmm13, xmm14, 2
	ret
case_1096:
	comiss xmm9, xmm10
	ret
case_1097:
	vcomiss xmm9, xmm10
	ret
case_1098:
	vucomiss xmm9, xmm11
	ret
case_1099:
	vcomisd xmm13, xmm14
	ret
case_1100:
	vucomisd xmm13, xmm15
	ret
case_1101:
	vroundps ymm1, ymm9, 0
	ret
case_1102:
	vroundps xmm1, xmm9, 0
	ret
case_1103:
	vroundpd ymm1, ymm13, 0
	ret
case_1104:
	vroundss xmm1, xmm2, xmm9, 0
	ret
case_1105:
	vroundsd xmm1, xmm2, xmm13, 0
	ret
case_1106:
	roundps xmm1, xmm9, 0
	ret
case_1107:
	roundsd xmm1, xmm13, 0
	ret
case_1108:
	vroundps ymm1, ymm9, 1
	ret
case_1109:
	vroundps xmm1, xmm9, 1
	ret
case_1110:
	vroundpd ymm1, ymm13, 1
	ret
case_1111:
	vroundss xmm1, xmm2, xmm9, 1
	ret
case_1112:
	vroundsd xmm1, xmm2, xmm13, 1
	ret
case_1113:
	roundps xmm1, xmm9, 1
	ret
case_1114:
	roundsd xmm1, xmm13, 1
	ret
case_1115:
	vroundps ymm1, ymm9, 2
	ret
case_1116:
	vroundps xmm1, xmm9, 2
	ret
case_1117:
	vroundpd ymm1, ymm13, 2
	ret
case_1118:
	vroundss xmm1, xmm2, xmm9, 2
	ret
case_1119:
	vroundsd xmm1, xmm2, xmm13, 2
	ret
case_1120:
	roundps xmm1, xmm9, 2
	ret
case_1121:
	roundsd xmm1, xmm13, 2
	ret
case_1122:
	vroundps ymm1, ymm9, 3
	ret
case_1123:
	vroundps xmm1, xmm9, 3
	ret
case_1124:
	vroundpd ymm1, ymm13, 3
	ret
case_1125:
	vroundss xmm1, xmm2, xmm9, 3
	ret
case_1126:
	vroundsd xmm1, xmm2, xmm13, 3
	ret
case_1127:
	roundps xmm1, xmm9, 3
	ret
case_1128:
	roundsd xmm1, xmm13, 3
	ret
case_1129:
	vroundps ymm1, ymm9, 4
	ret
case_1130:
	vroundps xmm1, xmm9, 4
	ret
case_1131:
	vroundpd ymm1, ymm13, 4
	ret
case_1132:
	vroundss xmm1, xmm2, xmm9, 4
	ret
case_1133:
	vroundsd xmm1, xmm2, xmm13, 4
	ret
case_1134:
	roundps xmm1, xmm9, 4
	ret
case_1135:
	roundsd xmm1, xmm13, 4
	ret
case_1136:
	vroundps ymm1, ymm9, 9
	ret
case_1137:
	vroundps xmm1, xmm9, 9
	ret
case_1138:
	vroundpd ymm1, ymm13, 9
	ret
case_1139:
	vroundss xmm1, xmm2, xmm9, 9
	ret
case_1140:
	vroundsd xmm1, xmm2, xmm13, 9
	ret
case_1141:
	roundps xmm1, xmm9, 9
	ret
case_1142:
	roundsd xmm1, xmm13, 9
	ret
case_1143:
	vcvtdq2ps ymm1, ymm2
	ret
case_1144:
	vcvtdq2ps xmm1, xmm2
	ret
case_1145:
	vcvtdq2pd ymm1, xmm2
	ret
case_1146:
	vcvtdq2pd xmm1, xmm2
	ret
case_1147:
	vcvtps2dq ymm1, ymm9
	ret
case_1148:
	vcvtps2dq xmm1, xmm9
	ret
case_1149:
	vcvttps2dq ymm1, ymm9
	ret
case_1150:
	vcvttps2dq xmm1, xmm9
	ret
case_1151:
	vcvtpd2dq xmm1, ymm13
	ret
case_1152:
	vcvtpd2dq xmm1, xmm13
	ret
case_1153:
	vcvttpd2dq xmm1, ymm13
	ret
case_1154:
	vcvttpd2dq xmm1, xmm13
	ret
case_1155:
	vcvtps2pd ymm1, xmm9
	ret
case_1156:
	vcvtps2pd xmm1, xmm9
	ret
case_1157:
	vcvtpd2ps xmm1, ymm13
	ret
case_1158:
	vcvtpd2ps xmm1, xmm13
	ret
case_1159:
	vcvtsi2ss xmm1, xmm2, eax
	ret
case_1160:
	vcvtsi2sd xmm1, xmm2, rax
	ret
case_1161:
	vcvtss2sd xmm1, xmm2, xmm9
	ret
case_1162:
	vcvtsd2ss xmm1, xmm2, xmm13
	ret
case_1163:
	vcvtsd2si rax, xmm13
	ret
case_1164:
	vcvttsd2si rax, xmm13
	ret
case_1165:
	vcvtss2si eax, xmm9
	ret
case_1166:
	vcvttss2si eax, xmm9
	ret
case_1167:
	vcvtph2ps ymm1, xmm2
	ret
case_1168:
	vcvtph2ps xmm1, xmm2
	ret
case_1169:
	vcvtps2ph xmm1, ymm9, 0
	ret
case_1170:
	vcvtps2ph xmm1, xmm9, 0
	ret
case_1171:
	vdppd xmm1, xmm13, xmm14, 0x31
	ret
case_1172:
	vdpps xmm1, xmm9, xmm10, 0xf1
	ret
case_1173:
	vdpps ymm1, ymm9, ymm10, 0x7f
	ret
case_1174:
	vmpsadbw xmm1, xmm2, xmm3, 5
	ret
case_1175:
	vmpsadbw ymm1, ymm2, ymm3, 0x2d
	ret
case_1176:
	vphminposuw xmm1, xmm2
	ret
case_1177:
	phminposuw xmm1, xmm2
	ret
case_1178:
	mpsadbw xmm1, xmm2, 5
	ret
case_1179:
	dppd xmm13, xmm14, 0x31
	ret
case_1180:
	dpps xmm9, xmm10, 0xf1
	ret
case_1181:
	vfmadd132ps ymm9, ymm10, ymm11
	ret
case_1182:
	vfmadd132ps xmm9, xmm10, xmm11
	ret
case_1183:
	vfmadd132pd ymm13, ymm14, ymm15
	ret
case_1184:
	vfmadd132pd xmm13, xmm14, xmm15
	ret
case_1185:
	vfmadd132ss xmm9, xmm10, xmm11
	ret
case_1186:
	vfmadd132sd xmm13, xmm14, xmm15
	ret
case_1187:
	vfmadd213ps ymm9, ymm10, ymm11
	ret
case_1188:
	vfmadd213ps xmm9, xmm10, xmm11
	ret
case_1189:
	vfmadd213pd ymm13, ymm14, ymm15
	ret
case_1190:
	vfmadd213pd xmm13, xmm14, xmm15
	ret
case_1191:
	vfmadd213ss xmm9, xmm10, xmm11
	ret
case_1192:
	vfmadd213sd xmm13, xmm14, xmm15
	ret
case_1193:
	vfmadd231ps ymm9, ymm10, ymm11
	ret
case_1194:
	vfmadd231ps xmm9, xmm10, xmm11
	ret
case_1195:
	vfmadd231pd ymm13, ymm14, ymm15
	ret
case_1196:
	vfmadd231pd xmm13, xmm14, xmm15
	ret
case_1197:
	vfmadd231ss xmm9, xmm10, xmm11
	ret
case_1198:
	vfmadd231sd xmm13, xmm14, xmm15
	ret
case_1199:
	vfmsub132ps ymm9, ymm10, ymm11
	ret
case_1200:
	vfmsub132ps xmm9, xmm10, xmm11
	ret
case_1201:
	vfmsub132pd ymm13, ymm14, ymm15
	ret
case_1202:
	vfmsub132pd xmm13, xmm14, xmm15
	ret
case_1203:
	vfmsub132ss xmm9, xmm10, xmm11
	ret
case_1204:
	vfmsub132sd xmm13, xmm14, xmm15
	ret
case_1205:
	vfmsub213ps ymm9, ymm10, ymm11
	ret
case_1206:
	vfmsub213ps xmm9, xmm10, xmm11
	ret
case_1207:
	vfmsub213pd ymm13, ymm14, ymm15
	ret
case_1208:
	vfmsub213pd xmm13, xmm14, xmm15
	ret
case_1209:
	vfmsub213ss xmm9, xmm10, xmm11
	ret
case_1210:
	vfmsub213sd xmm13, xmm14, xmm15
	ret
case_1211:
	vfmsub231ps ymm9, ymm10, ymm11
	ret
case_1212:
	vfmsub231ps xmm9, xmm10, xmm11
	ret
case_1213:
	vfmsub231pd ymm13, ymm14, ymm15
	ret
case_1214:
	vfmsub231pd xmm13, xmm14, xmm15
	ret
case_1215:
	vfmsub231ss xmm9, xmm10, xmm11
	ret
case_1216:
	vfmsub231sd xmm13, xmm14, xmm15
	ret
case_1217:
	vfnmadd132ps ymm9, ymm10, ymm11
	ret
case_1218:
	vfnmadd132ps xmm9, xmm10, xmm11
	ret
case_1219:
	vfnmadd132pd ymm13, ymm14, ymm15
	ret
case_1220:
	vfnmadd132pd xmm13, xmm14, xmm15
	ret
case_1221:
	vfnmadd132ss xmm9, xmm10, xmm11
	ret
case_1222:
	vfnmadd132sd xmm13, xmm14, xmm15
	ret
case_1223:
	vfnmadd213ps ymm9, ymm10, ymm11
	ret
case_1224:
	vfnmadd213ps xmm9, xmm10, xmm11
	ret
case_1225:
	vfnmadd213pd ymm13, ymm14, ymm15
	ret
case_1226:
	vfnmadd213pd xmm13, xmm14, xmm15
	ret
case_1227:
	vfnmadd213ss xmm9, xmm10, xmm11
	ret
case_1228:
	vfnmadd213sd xmm13, xmm14, xmm15
	ret
case_1229:
	vfnmadd231ps ymm9, ymm10, ymm11
	ret
case_1230:
	vfnmadd231ps xmm9, xmm10, xmm11
	ret
case_1231:
	vfnmadd231pd ymm13, ymm14, ymm15
	ret
case_1232:
	vfnmadd231pd xmm13, xmm14, xmm15
	ret
case_1233:
	vfnmadd231ss xmm9, xmm10, xmm11
	ret
case_1234:
	vfnmadd231sd xmm13, xmm14, xmm15
	ret
case_1235:
	vfnmsub132ps ymm9, ymm10, ymm11
	ret
case_1236:
	vfnmsub132ps xmm9, xmm10, xmm11
	ret
case_1237:
	vfnmsub132pd ymm13, ymm14, ymm15
	ret
case_1238:
	vfnmsub132pd xmm13, xmm14, xmm15
	ret
case_1239:
	vfnmsub132ss xmm9, xmm10, xmm11
	ret
case_1240:
	vfnmsub132sd xmm13, xmm14, xmm15
	ret
case_1241:
	vfnmsub213ps ymm9, ymm10, ymm11
	ret
case_1242:
	vfnmsub213ps xmm9, xmm10, xmm11
	ret
case_1243:
	vfnmsub213pd ymm13, ymm14, ymm15
	ret
case_1244:
	vfnmsub213pd xmm13, xmm14, xmm15
	ret
case_1245:
	vfnmsub213ss xmm9, xmm10, xmm11
	ret
case_1246:
	vfnmsub213sd xmm13, xmm14, xmm15
	ret
case_1247:
	vfnmsub231ps ymm9, ymm10, ymm11
	ret
case_1248:
	vfnmsub231ps xmm9, xmm10, xmm11
	ret
case_1249:
	vfnmsub231pd ymm13, ymm14, ymm15
	ret
case_1250:
	vfnmsub231pd xmm13, xmm14, xmm15
	ret
case_1251:
	vfnmsub231ss xmm9, xmm10, xmm11
	ret
case_1252:
	vfnmsub231sd xmm13, xmm14, xmm15
	ret
case_1253:
	vfmaddsub132ps ymm9, ymm10, ymm11
	ret
case_1254:
	vfmaddsub132pd ymm13, ymm14, ymm15
	ret
case_1255:
	vfmaddsub213ps ymm9, ymm10, ymm11
	ret
case_1256:
	vfmaddsub213pd ymm13, ymm14, ymm15
	ret
case_1257:
	vfmaddsub231ps ymm9, ymm10, ymm11
	ret
case_1258:
	vfmaddsub231pd ymm13, ymm14, ymm15
	ret
case_1259:
	vfmsubadd132ps ymm9, ymm10, ymm11
	ret
case_1260:
	vfmsubadd132pd ymm13, ymm14, ymm15
	ret
case_1261:
	vfmsubadd213ps ymm9, ymm10, ymm11
	ret
case_1262:
	vfmsubadd213pd ymm13, ymm14, ymm15
	ret
case_1263:
	vfmsubadd231ps ymm9, ymm10, ymm11
	ret
case_1264:
	vfmsubadd231pd ymm13, ymm14, ymm15
	ret
case_1265:
	andn r8, rax, rbx
	ret
case_1266:
	andn r8d, eax, ebx
	ret
case_1267:
	bextr r8, rax, rcx
	ret
case_1268:
	blsi r8, rax
	ret
case_1269:
	blsmsk r8, rax
	ret
case_1270:
	blsr r8, rax
	ret
case_1271:
	bzhi r8, rax, rcx
	ret
case_1272:
	mulx r8, r9, rax
	ret
case_1273:
	pdep r8, rax, rbx
	ret
case_1274:
	pext r8, rax, rbx
	ret
case_1275:
	rorx r8, rax, 13
	ret
case_1276:
	rorx r8d, eax, 13
	ret
case_1277:
	sarx r8, rax, rcx
	ret
case_1278:
	shlx r8, rax, rcx
	ret
case_1279:
	shrx r8, rax, rcx
	ret
case_1280:
	shlx r8d, eax, ecx
	ret
case_1281:
	shrx r8d, eax, ecx
	ret
case_1282:
	sarx r8d, eax, ecx
	ret
case_1283:
	tzcnt r8, rax
	ret
case_1284:
	tzcnt r8d, ebx
	ret
case_1285:
	lzcnt r8, rax
	ret
case_1286:
	lzcnt r8d, ebx
	ret
case_1287:
	popcnt r8, rax
	ret
case_1288:
	movbe r8, [rsi]
	ret
case_1289:
	movbe r8d, [rsi]
	ret
case_1290:
	movbe [rdi], rax
	ret
case_1291:
	movbe [rdi], eax
	ret
case_1292:
	crc32 r8d, al
	ret
case_1293:
	crc32 r8, rax
	ret
case_1294:
	crc32 r8d, eax
	ret
case_1295:
	cmpxchg16b [rdi]
	ret
case_1296:
	lzcnt rax, rax
	ret
case_1297:
	lzcnt ebx, ebx
	ret
case_1298:
	tzcnt rax, rax
	ret
case_1299:
	tzcnt ebx, ebx
	ret
case_1300:
	mov rax, rsi
	lzcnt rax, [rax]
	ret
case_1301:
	mov rax, rsi
	tzcnt rax, [rax]
	ret
case_1302:
	blsi rax, rax
	ret
case_1303:
	blsr rax, rax
	ret
case_1304:
	blsmsk rax, rax
	ret
case_1305:
	mulx rax, rbx, rax
	ret
case_1306:
	pdep rax, rax, rax
	ret
case_1307:
	pext rax, rax, rax
	ret
case_1308:
	rorx rax, rax, 5
	ret
case_1309:
	andn rax, rax, rbx
	ret
case_1310:
	bzhi rax, rax, rcx
	ret
case_1311:
	shlx rax, rax, rax
	ret
case_1312:
	popcnt rax, rax
	ret
case_1313:
	movbe rax, [rsi]
	ret
case_1314:
	pcmpistri xmm2, xmm3, 0
	ret
case_1315:
	pcmpistri xmm2, xmm3, 0x1a
	ret
case_1316:
	pcmpistrm xmm2, xmm3, 0x40
	ret
case_1317:
	pcmpestri xmm2, xmm3, 0x0c
	ret
case_1318:
	pcmpestrm xmm2, xmm3, 0x40
	ret
case_1319:
	vpcmpistri xmm2, xmm3, 0
	ret
case_1320:
	vpcmpistri xmm6, xmm7, 0x08
	ret
case_1321:
	vpcmpistri xmm6, xmm7, 0x1a
	ret
case_1322:
	vpcmpistrm xmm6, xmm7, 0x40
	ret
case_1323:
	vpcmpestri xmm6, xmm7, 0x0c
	ret
case_1324:
	vpcmpestrm xmm6, xmm7, 0x40
	ret
case_1325:
	mov eax, 6
	xor edx, edx
	lea r8, [rip + xarea]
	xsave [r8]
	vpxor ymm1, ymm1, ymm1
	vpxor xmm9, xmm9, xmm9
	xrstor [r8]
	xor r8d, r8d
	mov eax, 0x33
	xor edx, edx
	ret
case_1326:
	vpgatherdd ymm1, [r10 + ymm5*4], ymm6
	ret
case_1327:
	vpgatherdq ymm1, [r10 + xmm5*2], ymm6
	ret
case_1328:
	vpgatherqq ymm1, [r10 + ymm5*2], ymm6
	ret
case_1329:
	vgatherdps ymm1, [r10 + ymm5*4], ymm6
	ret
case_1330:
	vgatherdpd ymm1, [r10 + xmm5*2], ymm6
	ret
case_1331:
	vpgatherdd xmm1, [r10 + xmm5*4], xmm6
	ret
.bss
.p2align 6
xarea:
	.space 4096
.section .rodata
name_0:
	.asciz "paddb xmm1, xmm2"
name_1:
	.asciz "paddb xmm1, [rsi]"
name_2:
	.asciz "vpaddb xmm1, xmm2, xmm3"
name_3:
	.asciz "vpaddb xmm1, xmm2, [rsi]"
name_4:
	.asciz "vpaddb ymm1, ymm2, ymm3"
name_5:
	.asciz "vpaddb ymm1, ymm2, [rsi]"
name_6:
	.asciz "paddw xmm1, xmm2"
name_7:
	.asciz "paddw xmm1, [rsi]"
name_8:
	.asciz "vpaddw xmm1, xmm2, xmm3"
name_9:
	.asciz "vpaddw xmm1, xmm2, [rsi]"
name_10:
	.asciz "vpaddw ymm1, ymm2, ymm3"
name_11:
	.asciz "vpaddw ymm1, ymm2, [rsi]"
name_12:
	.asciz "paddd xmm1, xmm2"
name_13:
	.asciz "paddd xmm1, [rsi]"
name_14:
	.asciz "vpaddd xmm1, xmm2, xmm3"
name_15:
	.asciz "vpaddd xmm1, xmm2, [rsi]"
name_16:
	.asciz "vpaddd ymm1, ymm2, ymm3"
name_17:
	.asciz "vpaddd ymm1, ymm2, [rsi]"
name_18:
	.asciz "paddq xmm1, xmm2"
name_19:
	.asciz "paddq xmm1, [rsi]"
name_20:
	.asciz "vpaddq xmm1, xmm2, xmm3"
name_21:
	.asciz "vpaddq xmm1, xmm2, [rsi]"
name_22:
	.asciz "vpaddq ymm1, ymm2, ymm3"
name_23:
	.asciz "vpaddq ymm1, ymm2, [rsi]"
name_24:
	.asciz "psubb xmm1, xmm2"
name_25:
	.asciz "psubb xmm1, [rsi]"
name_26:
	.asciz "vpsubb xmm1, xmm2, xmm3"
name_27:
	.asciz "vpsubb xmm1, xmm2, [rsi]"
name_28:
	.asciz "vpsubb ymm1, ymm2, ymm3"
name_29:
	.asciz "vpsubb ymm1, ymm2, [rsi]"
name_30:
	.asciz "psubw xmm1, xmm2"
name_31:
	.asciz "psubw xmm1, [rsi]"
name_32:
	.asciz "vpsubw xmm1, xmm2, xmm3"
name_33:
	.asciz "vpsubw xmm1, xmm2, [rsi]"
name_34:
	.asciz "vpsubw ymm1, ymm2, ymm3"
name_35:
	.asciz "vpsubw ymm1, ymm2, [rsi]"
name_36:
	.asciz "psubd xmm1, xmm2"
name_37:
	.asciz "psubd xmm1, [rsi]"
name_38:
	.asciz "vpsubd xmm1, xmm2, xmm3"
name_39:
	.asciz "vpsubd xmm1, xmm2, [rsi]"
name_40:
	.asciz "vpsubd ymm1, ymm2, ymm3"
name_41:
	.asciz "vpsubd ymm1, ymm2, [rsi]"
name_42:
	.asciz "psubq xmm1, xmm2"
name_43:
	.asciz "psubq xmm1, [rsi]"
name_44:
	.asciz "vpsubq xmm1, xmm2, xmm3"
name_45:
	.asciz "vpsubq xmm1, xmm2, [rsi]"
name_46:
	.asciz "vpsubq ymm1, ymm2, ymm3"
name_47:
	.asciz "vpsubq ymm1, ymm2, [rsi]"
name_48:
	.asciz "paddsb xmm1, xmm2"
name_49:
	.asciz "paddsb xmm1, [rsi]"
name_50:
	.asciz "vpaddsb xmm1, xmm2, xmm3"
name_51:
	.asciz "vpaddsb xmm1, xmm2, [rsi]"
name_52:
	.asciz "vpaddsb ymm1, ymm2, ymm3"
name_53:
	.asciz "vpaddsb ymm1, ymm2, [rsi]"
name_54:
	.asciz "paddsw xmm1, xmm2"
name_55:
	.asciz "paddsw xmm1, [rsi]"
name_56:
	.asciz "vpaddsw xmm1, xmm2, xmm3"
name_57:
	.asciz "vpaddsw xmm1, xmm2, [rsi]"
name_58:
	.asciz "vpaddsw ymm1, ymm2, ymm3"
name_59:
	.asciz "vpaddsw ymm1, ymm2, [rsi]"
name_60:
	.asciz "paddusb xmm1, xmm2"
name_61:
	.asciz "paddusb xmm1, [rsi]"
name_62:
	.asciz "vpaddusb xmm1, xmm2, xmm3"
name_63:
	.asciz "vpaddusb xmm1, xmm2, [rsi]"
name_64:
	.asciz "vpaddusb ymm1, ymm2, ymm3"
name_65:
	.asciz "vpaddusb ymm1, ymm2, [rsi]"
name_66:
	.asciz "paddusw xmm1, xmm2"
name_67:
	.asciz "paddusw xmm1, [rsi]"
name_68:
	.asciz "vpaddusw xmm1, xmm2, xmm3"
name_69:
	.asciz "vpaddusw xmm1, xmm2, [rsi]"
name_70:
	.asciz "vpaddusw ymm1, ymm2, ymm3"
name_71:
	.asciz "vpaddusw ymm1, ymm2, [rsi]"
name_72:
	.asciz "psubsb xmm1, xmm2"
name_73:
	.asciz "psubsb xmm1, [rsi]"
name_74:
	.asciz "vpsubsb xmm1, xmm2, xmm3"
name_75:
	.asciz "vpsubsb xmm1, xmm2, [rsi]"
name_76:
	.asciz "vpsubsb ymm1, ymm2, ymm3"
name_77:
	.asciz "vpsubsb ymm1, ymm2, [rsi]"
name_78:
	.asciz "psubsw xmm1, xmm2"
name_79:
	.asciz "psubsw xmm1, [rsi]"
name_80:
	.asciz "vpsubsw xmm1, xmm2, xmm3"
name_81:
	.asciz "vpsubsw xmm1, xmm2, [rsi]"
name_82:
	.asciz "vpsubsw ymm1, ymm2, ymm3"
name_83:
	.asciz "vpsubsw ymm1, ymm2, [rsi]"
name_84:
	.asciz "psubusb xmm1, xmm2"
name_85:
	.asciz "psubusb xmm1, [rsi]"
name_86:
	.asciz "vpsubusb xmm1, xmm2, xmm3"
name_87:
	.asciz "vpsubusb xmm1, xmm2, [rsi]"
name_88:
	.asciz "vpsubusb ymm1, ymm2, ymm3"
name_89:
	.asciz "vpsubusb ymm1, ymm2, [rsi]"
name_90:
	.asciz "psubusw xmm1, xmm2"
name_91:
	.asciz "psubusw xmm1, [rsi]"
name_92:
	.asciz "vpsubusw xmm1, xmm2, xmm3"
name_93:
	.asciz "vpsubusw xmm1, xmm2, [rsi]"
name_94:
	.asciz "vpsubusw ymm1, ymm2, ymm3"
name_95:
	.asciz "vpsubusw ymm1, ymm2, [rsi]"
name_96:
	.asciz "pavgb xmm1, xmm2"
name_97:
	.asciz "pavgb xmm1, [rsi]"
name_98:
	.asciz "vpavgb xmm1, xmm2, xmm3"
name_99:
	.asciz "vpavgb xmm1, xmm2, [rsi]"
name_100:
	.asciz "vpavgb ymm1, ymm2, ymm3"
name_101:
	.asciz "vpavgb ymm1, ymm2, [rsi]"
name_102:
	.asciz "pavgw xmm1, xmm2"
name_103:
	.asciz "pavgw xmm1, [rsi]"
name_104:
	.asciz "vpavgw xmm1, xmm2, xmm3"
name_105:
	.asciz "vpavgw xmm1, xmm2, [rsi]"
name_106:
	.asciz "vpavgw ymm1, ymm2, ymm3"
name_107:
	.asciz "vpavgw ymm1, ymm2, [rsi]"
name_108:
	.asciz "pmaxsb xmm1, xmm2"
name_109:
	.asciz "pmaxsb xmm1, [rsi]"
name_110:
	.asciz "vpmaxsb xmm1, xmm2, xmm3"
name_111:
	.asciz "vpmaxsb xmm1, xmm2, [rsi]"
name_112:
	.asciz "vpmaxsb ymm1, ymm2, ymm3"
name_113:
	.asciz "vpmaxsb ymm1, ymm2, [rsi]"
name_114:
	.asciz "pmaxsw xmm1, xmm2"
name_115:
	.asciz "pmaxsw xmm1, [rsi]"
name_116:
	.asciz "vpmaxsw xmm1, xmm2, xmm3"
name_117:
	.asciz "vpmaxsw xmm1, xmm2, [rsi]"
name_118:
	.asciz "vpmaxsw ymm1, ymm2, ymm3"
name_119:
	.asciz "vpmaxsw ymm1, ymm2, [rsi]"
name_120:
	.asciz "pmaxsd xmm1, xmm2"
name_121:
	.asciz "pmaxsd xmm1, [rsi]"
name_122:
	.asciz "vpmaxsd xmm1, xmm2, xmm3"
name_123:
	.asciz "vpmaxsd xmm1, xmm2, [rsi]"
name_124:
	.asciz "vpmaxsd ymm1, ymm2, ymm3"
name_125:
	.asciz "vpmaxsd ymm1, ymm2, [rsi]"
name_126:
	.asciz "pmaxub xmm1, xmm2"
name_127:
	.asciz "pmaxub xmm1, [rsi]"
name_128:
	.asciz "vpmaxub xmm1, xmm2, xmm3"
name_129:
	.asciz "vpmaxub xmm1, xmm2, [rsi]"
name_130:
	.asciz "vpmaxub ymm1, ymm2, ymm3"
name_131:
	.asciz "vpmaxub ymm1, ymm2, [rsi]"
name_132:
	.asciz "pmaxuw xmm1, xmm2"
name_133:
	.asciz "pmaxuw xmm1, [rsi]"
name_134:
	.asciz "vpmaxuw xmm1, xmm2, xmm3"
name_135:
	.asciz "vpmaxuw xmm1, xmm2, [rsi]"
name_136:
	.asciz "vpmaxuw ymm1, ymm2, ymm3"
name_137:
	.asciz "vpmaxuw ymm1, ymm2, [rsi]"
name_138:
	.asciz "pmaxud xmm1, xmm2"
name_139:
	.asciz "pmaxud xmm1, [rsi]"
name_140:
	.asciz "vpmaxud xmm1, xmm2, xmm3"
name_141:
	.asciz "vpmaxud xmm1, xmm2, [rsi]"
name_142:
	.asciz "vpmaxud ymm1, ymm2, ymm3"
name_143:
	.asciz "vpmaxud ymm1, ymm2, [rsi]"
name_144:
	.asciz "pminsb xmm1, xmm2"
name_145:
	.asciz "pminsb xmm1, [rsi]"
name_146:
	.asciz "vpminsb xmm1, xmm2, xmm3"
name_147:
	.asciz "vpminsb xmm1, xmm2, [rsi]"
name_148:
	.asciz "vpminsb ymm1, ymm2, ymm3"
name_149:
	.asciz "vpminsb ymm1, ymm2, [rsi]"
name_150:
	.asciz "pminsw xmm1, xmm2"
name_151:
	.asciz "pminsw xmm1, [rsi]"
name_152:
	.asciz "vpminsw xmm1, xmm2, xmm3"
name_153:
	.asciz "vpminsw xmm1, xmm2, [rsi]"
name_154:
	.asciz "vpminsw ymm1, ymm2, ymm3"
name_155:
	.asciz "vpminsw ymm1, ymm2, [rsi]"
name_156:
	.asciz "pminsd xmm1, xmm2"
name_157:
	.asciz "pminsd xmm1, [rsi]"
name_158:
	.asciz "vpminsd xmm1, xmm2, xmm3"
name_159:
	.asciz "vpminsd xmm1, xmm2, [rsi]"
name_160:
	.asciz "vpminsd ymm1, ymm2, ymm3"
name_161:
	.asciz "vpminsd ymm1, ymm2, [rsi]"
name_162:
	.asciz "pminub xmm1, xmm2"
name_163:
	.asciz "pminub xmm1, [rsi]"
name_164:
	.asciz "vpminub xmm1, xmm2, xmm3"
name_165:
	.asciz "vpminub xmm1, xmm2, [rsi]"
name_166:
	.asciz "vpminub ymm1, ymm2, ymm3"
name_167:
	.asciz "vpminub ymm1, ymm2, [rsi]"
name_168:
	.asciz "pminuw xmm1, xmm2"
name_169:
	.asciz "pminuw xmm1, [rsi]"
name_170:
	.asciz "vpminuw xmm1, xmm2, xmm3"
name_171:
	.asciz "vpminuw xmm1, xmm2, [rsi]"
name_172:
	.asciz "vpminuw ymm1, ymm2, ymm3"
name_173:
	.asciz "vpminuw ymm1, ymm2, [rsi]"
name_174:
	.asciz "pminud xmm1, xmm2"
name_175:
	.asciz "pminud xmm1, [rsi]"
name_176:
	.asciz "vpminud xmm1, xmm2, xmm3"
name_177:
	.asciz "vpminud xmm1, xmm2, [rsi]"
name_178:
	.asciz "vpminud ymm1, ymm2, ymm3"
name_179:
	.asciz "vpminud ymm1, ymm2, [rsi]"
name_180:
	.asciz "pcmpeqb xmm1, xmm2"
name_181:
	.asciz "pcmpeqb xmm1, [rsi]"
name_182:
	.asciz "vpcmpeqb xmm1, xmm2, xmm3"
name_183:
	.asciz "vpcmpeqb xmm1, xmm2, [rsi]"
name_184:
	.asciz "vpcmpeqb ymm1, ymm2, ymm3"
name_185:
	.asciz "vpcmpeqb ymm1, ymm2, [rsi]"
name_186:
	.asciz "pcmpeqw xmm1, xmm2"
name_187:
	.asciz "pcmpeqw xmm1, [rsi]"
name_188:
	.asciz "vpcmpeqw xmm1, xmm2, xmm3"
name_189:
	.asciz "vpcmpeqw xmm1, xmm2, [rsi]"
name_190:
	.asciz "vpcmpeqw ymm1, ymm2, ymm3"
name_191:
	.asciz "vpcmpeqw ymm1, ymm2, [rsi]"
name_192:
	.asciz "pcmpeqd xmm1, xmm2"
name_193:
	.asciz "pcmpeqd xmm1, [rsi]"
name_194:
	.asciz "vpcmpeqd xmm1, xmm2, xmm3"
name_195:
	.asciz "vpcmpeqd xmm1, xmm2, [rsi]"
name_196:
	.asciz "vpcmpeqd ymm1, ymm2, ymm3"
name_197:
	.asciz "vpcmpeqd ymm1, ymm2, [rsi]"
name_198:
	.asciz "pcmpeqq xmm1, xmm2"
name_199:
	.asciz "pcmpeqq xmm1, [rsi]"
name_200:
	.asciz "vpcmpeqq xmm1, xmm2, xmm3"
name_201:
	.asciz "vpcmpeqq xmm1, xmm2, [rsi]"
name_202:
	.asciz "vpcmpeqq ymm1, ymm2, ymm3"
name_203:
	.asciz "vpcmpeqq ymm1, ymm2, [rsi]"
name_204:
	.asciz "pcmpgtb xmm1, xmm2"
name_205:
	.asciz "pcmpgtb xmm1, [rsi]"
name_206:
	.asciz "vpcmpgtb xmm1, xmm2, xmm3"
name_207:
	.asciz "vpcmpgtb xmm1, xmm2, [rsi]"
name_208:
	.asciz "vpcmpgtb ymm1, ymm2, ymm3"
name_209:
	.asciz "vpcmpgtb ymm1, ymm2, [rsi]"
name_210:
	.asciz "pcmpgtw xmm1, xmm2"
name_211:
	.asciz "pcmpgtw xmm1, [rsi]"
name_212:
	.asciz "vpcmpgtw xmm1, xmm2, xmm3"
name_213:
	.asciz "vpcmpgtw xmm1, xmm2, [rsi]"
name_214:
	.asciz "vpcmpgtw ymm1, ymm2, ymm3"
name_215:
	.asciz "vpcmpgtw ymm1, ymm2, [rsi]"
name_216:
	.asciz "pcmpgtd xmm1, xmm2"
name_217:
	.asciz "pcmpgtd xmm1, [rsi]"
name_218:
	.asciz "vpcmpgtd xmm1, xmm2, xmm3"
name_219:
	.asciz "vpcmpgtd xmm1, xmm2, [rsi]"
name_220:
	.asciz "vpcmpgtd ymm1, ymm2, ymm3"
name_221:
	.asciz "vpcmpgtd ymm1, ymm2, [rsi]"
name_222:
	.asciz "pcmpgtq xmm1, xmm2"
name_223:
	.asciz "pcmpgtq xmm1, [rsi]"
name_224:
	.asciz "vpcmpgtq xmm1, xmm2, xmm3"
name_225:
	.asciz "vpcmpgtq xmm1, xmm2, [rsi]"
name_226:
	.asciz "vpcmpgtq ymm1, ymm2, ymm3"
name_227:
	.asciz "vpcmpgtq ymm1, ymm2, [rsi]"
name_228:
	.asciz "pand xmm1, xmm2"
name_229:
	.asciz "pand xmm1, [rsi]"
name_230:
	.asciz "vpand xmm1, xmm2, xmm3"
name_231:
	.asciz "vpand xmm1, xmm2, [rsi]"
name_232:
	.asciz "vpand ymm1, ymm2, ymm3"
name_233:
	.asciz "vpand ymm1, ymm2, [rsi]"
name_234:
	.asciz "pandn xmm1, xmm2"
name_235:
	.asciz "pandn xmm1, [rsi]"
name_236:
	.asciz "vpandn xmm1, xmm2, xmm3"
name_237:
	.asciz "vpandn xmm1, xmm2, [rsi]"
name_238:
	.asciz "vpandn ymm1, ymm2, ymm3"
name_239:
	.asciz "vpandn ymm1, ymm2, [rsi]"
name_240:
	.asciz "por xmm1, xmm2"
name_241:
	.asciz "por xmm1, [rsi]"
name_242:
	.asciz "vpor xmm1, xmm2, xmm3"
name_243:
	.asciz "vpor xmm1, xmm2, [rsi]"
name_244:
	.asciz "vpor ymm1, ymm2, ymm3"
name_245:
	.asciz "vpor ymm1, ymm2, [rsi]"
name_246:
	.asciz "pxor xmm1, xmm2"
name_247:
	.asciz "pxor xmm1, [rsi]"
name_248:
	.asciz "vpxor xmm1, xmm2, xmm3"
name_249:
	.asciz "vpxor xmm1, xmm2, [rsi]"
name_250:
	.asciz "vpxor ymm1, ymm2, ymm3"
name_251:
	.asciz "vpxor ymm1, ymm2, [rsi]"
name_252:
	.asciz "pmullw xmm1, xmm2"
name_253:
	.asciz "pmullw xmm1, [rsi]"
name_254:
	.asciz "vpmullw xmm1, xmm2, xmm3"
name_255:
	.asciz "vpmullw xmm1, xmm2, [rsi]"
name_256:
	.asciz "vpmullw ymm1, ymm2, ymm3"
name_257:
	.asciz "vpmullw ymm1, ymm2, [rsi]"
name_258:
	.asciz "pmulld xmm1, xmm2"
name_259:
	.asciz "pmulld xmm1, [rsi]"
name_260:
	.asciz "vpmulld xmm1, xmm2, xmm3"
name_261:
	.asciz "vpmulld xmm1, xmm2, [rsi]"
name_262:
	.asciz "vpmulld ymm1, ymm2, ymm3"
name_263:
	.asciz "vpmulld ymm1, ymm2, [rsi]"
name_264:
	.asciz "pmulhw xmm1, xmm2"
name_265:
	.asciz "pmulhw xmm1, [rsi]"
name_266:
	.asciz "vpmulhw xmm1, xmm2, xmm3"
name_267:
	.asciz "vpmulhw xmm1, xmm2, [rsi]"
name_268:
	.asciz "vpmulhw ymm1, ymm2, ymm3"
name_269:
	.asciz "vpmulhw ymm1, ymm2, [rsi]"
name_270:
	.asciz "pmulhuw xmm1, xmm2"
name_271:
	.asciz "pmulhuw xmm1, [rsi]"
name_272:
	.asciz "vpmulhuw xmm1, xmm2, xmm3"
name_273:
	.asciz "vpmulhuw xmm1, xmm2, [rsi]"
name_274:
	.asciz "vpmulhuw ymm1, ymm2, ymm3"
name_275:
	.asciz "vpmulhuw ymm1, ymm2, [rsi]"
name_276:
	.asciz "pmulhrsw xmm1, xmm2"
name_277:
	.asciz "pmulhrsw xmm1, [rsi]"
name_278:
	.asciz "vpmulhrsw xmm1, xmm2, xmm3"
name_279:
	.asciz "vpmulhrsw xmm1, xmm2, [rsi]"
name_280:
	.asciz "vpmulhrsw ymm1, ymm2, ymm3"
name_281:
	.asciz "vpmulhrsw ymm1, ymm2, [rsi]"
name_282:
	.asciz "pmuldq xmm1, xmm2"
name_283:
	.asciz "pmuldq xmm1, [rsi]"
name_284:
	.asciz "vpmuldq xmm1, xmm2, xmm3"
name_285:
	.asciz "vpmuldq xmm1, xmm2, [rsi]"
name_286:
	.asciz "vpmuldq ymm1, ymm2, ymm3"
name_287:
	.asciz "vpmuldq ymm1, ymm2, [rsi]"
name_288:
	.asciz "pmuludq xmm1, xmm2"
name_289:
	.asciz "pmuludq xmm1, [rsi]"
name_290:
	.asciz "vpmuludq xmm1, xmm2, xmm3"
name_291:
	.asciz "vpmuludq xmm1, xmm2, [rsi]"
name_292:
	.asciz "vpmuludq ymm1, ymm2, ymm3"
name_293:
	.asciz "vpmuludq ymm1, ymm2, [rsi]"
name_294:
	.asciz "pmaddwd xmm1, xmm2"
name_295:
	.asciz "pmaddwd xmm1, [rsi]"
name_296:
	.asciz "vpmaddwd xmm1, xmm2, xmm3"
name_297:
	.asciz "vpmaddwd xmm1, xmm2, [rsi]"
name_298:
	.asciz "vpmaddwd ymm1, ymm2, ymm3"
name_299:
	.asciz "vpmaddwd ymm1, ymm2, [rsi]"
name_300:
	.asciz "pmaddubsw xmm1, xmm2"
name_301:
	.asciz "pmaddubsw xmm1, [rsi]"
name_302:
	.asciz "vpmaddubsw xmm1, xmm2, xmm3"
name_303:
	.asciz "vpmaddubsw xmm1, xmm2, [rsi]"
name_304:
	.asciz "vpmaddubsw ymm1, ymm2, ymm3"
name_305:
	.asciz "vpmaddubsw ymm1, ymm2, [rsi]"
name_306:
	.asciz "psadbw xmm1, xmm2"
name_307:
	.asciz "psadbw xmm1, [rsi]"
name_308:
	.asciz "vpsadbw xmm1, xmm2, xmm3"
name_309:
	.asciz "vpsadbw xmm1, xmm2, [rsi]"
name_310:
	.asciz "vpsadbw ymm1, ymm2, ymm3"
name_311:
	.asciz "vpsadbw ymm1, ymm2, [rsi]"
name_312:
	.asciz "psignb xmm1, xmm2"
name_313:
	.asciz "psignb xmm1, [rsi]"
name_314:
	.asciz "vpsignb xmm1, xmm2, xmm3"
name_315:
	.asciz "vpsignb xmm1, xmm2, [rsi]"
name_316:
	.asciz "vpsignb ymm1, ymm2, ymm3"
name_317:
	.asciz "vpsignb ymm1, ymm2, [rsi]"
name_318:
	.asciz "psignw xmm1, xmm2"
name_319:
	.asciz "psignw xmm1, [rsi]"
name_320:
	.asciz "vpsignw xmm1, xmm2, xmm3"
name_321:
	.asciz "vpsignw xmm1, xmm2, [rsi]"
name_322:
	.asciz "vpsignw ymm1, ymm2, ymm3"
name_323:
	.asciz "vpsignw ymm1, ymm2, [rsi]"
name_324:
	.asciz "psignd xmm1, xmm2"
name_325:
	.asciz "psignd xmm1, [rsi]"
name_326:
	.asciz "vpsignd xmm1, xmm2, xmm3"
name_327:
	.asciz "vpsignd xmm1, xmm2, [rsi]"
name_328:
	.asciz "vpsignd ymm1, ymm2, ymm3"
name_329:
	.asciz "vpsignd ymm1, ymm2, [rsi]"
name_330:
	.asciz "punpcklbw xmm1, xmm2"
name_331:
	.asciz "punpcklbw xmm1, [rsi]"
name_332:
	.asciz "vpunpcklbw xmm1, xmm2, xmm3"
name_333:
	.asciz "vpunpcklbw xmm1, xmm2, [rsi]"
name_334:
	.asciz "vpunpcklbw ymm1, ymm2, ymm3"
name_335:
	.asciz "vpunpcklbw ymm1, ymm2, [rsi]"
name_336:
	.asciz "punpcklwd xmm1, xmm2"
name_337:
	.asciz "punpcklwd xmm1, [rsi]"
name_338:
	.asciz "vpunpcklwd xmm1, xmm2, xmm3"
name_339:
	.asciz "vpunpcklwd xmm1, xmm2, [rsi]"
name_340:
	.asciz "vpunpcklwd ymm1, ymm2, ymm3"
name_341:
	.asciz "vpunpcklwd ymm1, ymm2, [rsi]"
name_342:
	.asciz "punpckldq xmm1, xmm2"
name_343:
	.asciz "punpckldq xmm1, [rsi]"
name_344:
	.asciz "vpunpckldq xmm1, xmm2, xmm3"
name_345:
	.asciz "vpunpckldq xmm1, xmm2, [rsi]"
name_346:
	.asciz "vpunpckldq ymm1, ymm2, ymm3"
name_347:
	.asciz "vpunpckldq ymm1, ymm2, [rsi]"
name_348:
	.asciz "punpcklqdq xmm1, xmm2"
name_349:
	.asciz "punpcklqdq xmm1, [rsi]"
name_350:
	.asciz "vpunpcklqdq xmm1, xmm2, xmm3"
name_351:
	.asciz "vpunpcklqdq xmm1, xmm2, [rsi]"
name_352:
	.asciz "vpunpcklqdq ymm1, ymm2, ymm3"
name_353:
	.asciz "vpunpcklqdq ymm1, ymm2, [rsi]"
name_354:
	.asciz "punpckhbw xmm1, xmm2"
name_355:
	.asciz "punpckhbw xmm1, [rsi]"
name_356:
	.asciz "vpunpckhbw xmm1, xmm2, xmm3"
name_357:
	.asciz "vpunpckhbw xmm1, xmm2, [rsi]"
name_358:
	.asciz "vpunpckhbw ymm1, ymm2, ymm3"
name_359:
	.asciz "vpunpckhbw ymm1, ymm2, [rsi]"
name_360:
	.asciz "punpckhwd xmm1, xmm2"
name_361:
	.asciz "punpckhwd xmm1, [rsi]"
name_362:
	.asciz "vpunpckhwd xmm1, xmm2, xmm3"
name_363:
	.asciz "vpunpckhwd xmm1, xmm2, [rsi]"
name_364:
	.asciz "vpunpckhwd ymm1, ymm2, ymm3"
name_365:
	.asciz "vpunpckhwd ymm1, ymm2, [rsi]"
name_366:
	.asciz "punpckhdq xmm1, xmm2"
name_367:
	.asciz "punpckhdq xmm1, [rsi]"
name_368:
	.asciz "vpunpckhdq xmm1, xmm2, xmm3"
name_369:
	.asciz "vpunpckhdq xmm1, xmm2, [rsi]"
name_370:
	.asciz "vpunpckhdq ymm1, ymm2, ymm3"
name_371:
	.asciz "vpunpckhdq ymm1, ymm2, [rsi]"
name_372:
	.asciz "punpckhqdq xmm1, xmm2"
name_373:
	.asciz "punpckhqdq xmm1, [rsi]"
name_374:
	.asciz "vpunpckhqdq xmm1, xmm2, xmm3"
name_375:
	.asciz "vpunpckhqdq xmm1, xmm2, [rsi]"
name_376:
	.asciz "vpunpckhqdq ymm1, ymm2, ymm3"
name_377:
	.asciz "vpunpckhqdq ymm1, ymm2, [rsi]"
name_378:
	.asciz "packsswb xmm1, xmm2"
name_379:
	.asciz "packsswb xmm1, [rsi]"
name_380:
	.asciz "vpacksswb xmm1, xmm2, xmm3"
name_381:
	.asciz "vpacksswb xmm1, xmm2, [rsi]"
name_382:
	.asciz "vpacksswb ymm1, ymm2, ymm3"
name_383:
	.asciz "vpacksswb ymm1, ymm2, [rsi]"
name_384:
	.asciz "packuswb xmm1, xmm2"
name_385:
	.asciz "packuswb xmm1, [rsi]"
name_386:
	.asciz "vpackuswb xmm1, xmm2, xmm3"
name_387:
	.asciz "vpackuswb xmm1, xmm2, [rsi]"
name_388:
	.asciz "vpackuswb ymm1, ymm2, ymm3"
name_389:
	.asciz "vpackuswb ymm1, ymm2, [rsi]"
name_390:
	.asciz "packssdw xmm1, xmm2"
name_391:
	.asciz "packssdw xmm1, [rsi]"
name_392:
	.asciz "vpackssdw xmm1, xmm2, xmm3"
name_393:
	.asciz "vpackssdw xmm1, xmm2, [rsi]"
name_394:
	.asciz "vpackssdw ymm1, ymm2, ymm3"
name_395:
	.asciz "vpackssdw ymm1, ymm2, [rsi]"
name_396:
	.asciz "packusdw xmm1, xmm2"
name_397:
	.asciz "packusdw xmm1, [rsi]"
name_398:
	.asciz "vpackusdw xmm1, xmm2, xmm3"
name_399:
	.asciz "vpackusdw xmm1, xmm2, [rsi]"
name_400:
	.asciz "vpackusdw ymm1, ymm2, ymm3"
name_401:
	.asciz "vpackusdw ymm1, ymm2, [rsi]"
name_402:
	.asciz "pshufb xmm1, xmm2"
name_403:
	.asciz "pshufb xmm1, [rsi]"
name_404:
	.asciz "vpshufb xmm1, xmm2, xmm3"
name_405:
	.asciz "vpshufb xmm1, xmm2, [rsi]"
name_406:
	.asciz "vpshufb ymm1, ymm2, ymm3"
name_407:
	.asciz "vpshufb ymm1, ymm2, [rsi]"
name_408:
	.asciz "phaddw xmm1, xmm2"
name_409:
	.asciz "phaddw xmm1, [rsi]"
name_410:
	.asciz "vphaddw xmm1, xmm2, xmm3"
name_411:
	.asciz "vphaddw xmm1, xmm2, [rsi]"
name_412:
	.asciz "vphaddw ymm1, ymm2, ymm3"
name_413:
	.asciz "vphaddw ymm1, ymm2, [rsi]"
name_414:
	.asciz "phaddd xmm1, xmm2"
name_415:
	.asciz "phaddd xmm1, [rsi]"
name_416:
	.asciz "vphaddd xmm1, xmm2, xmm3"
name_417:
	.asciz "vphaddd xmm1, xmm2, [rsi]"
name_418:
	.asciz "vphaddd ymm1, ymm2, ymm3"
name_419:
	.asciz "vphaddd ymm1, ymm2, [rsi]"
name_420:
	.asciz "phaddsw xmm1, xmm2"
name_421:
	.asciz "phaddsw xmm1, [rsi]"
name_422:
	.asciz "vphaddsw xmm1, xmm2, xmm3"
name_423:
	.asciz "vphaddsw xmm1, xmm2, [rsi]"
name_424:
	.asciz "vphaddsw ymm1, ymm2, ymm3"
name_425:
	.asciz "vphaddsw ymm1, ymm2, [rsi]"
name_426:
	.asciz "phsubw xmm1, xmm2"
name_427:
	.asciz "phsubw xmm1, [rsi]"
name_428:
	.asciz "vphsubw xmm1, xmm2, xmm3"
name_429:
	.asciz "vphsubw xmm1, xmm2, [rsi]"
name_430:
	.asciz "vphsubw ymm1, ymm2, ymm3"
name_431:
	.asciz "vphsubw ymm1, ymm2, [rsi]"
name_432:
	.asciz "phsubd xmm1, xmm2"
name_433:
	.asciz "phsubd xmm1, [rsi]"
name_434:
	.asciz "vphsubd xmm1, xmm2, xmm3"
name_435:
	.asciz "vphsubd xmm1, xmm2, [rsi]"
name_436:
	.asciz "vphsubd ymm1, ymm2, ymm3"
name_437:
	.asciz "vphsubd ymm1, ymm2, [rsi]"
name_438:
	.asciz "phsubsw xmm1, xmm2"
name_439:
	.asciz "phsubsw xmm1, [rsi]"
name_440:
	.asciz "vphsubsw xmm1, xmm2, xmm3"
name_441:
	.asciz "vphsubsw xmm1, xmm2, [rsi]"
name_442:
	.asciz "vphsubsw ymm1, ymm2, ymm3"
name_443:
	.asciz "vphsubsw ymm1, ymm2, [rsi]"
name_444:
	.asciz "pabsb xmm1, xmm2"
name_445:
	.asciz "vpabsb xmm1, xmm2"
name_446:
	.asciz "vpabsb ymm1, ymm2"
name_447:
	.asciz "vpabsb ymm1, [rsi]"
name_448:
	.asciz "pabsw xmm1, xmm2"
name_449:
	.asciz "vpabsw xmm1, xmm2"
name_450:
	.asciz "vpabsw ymm1, ymm2"
name_451:
	.asciz "vpabsw ymm1, [rsi]"
name_452:
	.asciz "pabsd xmm1, xmm2"
name_453:
	.asciz "vpabsd xmm1, xmm2"
name_454:
	.asciz "vpabsd ymm1, ymm2"
name_455:
	.asciz "vpabsd ymm1, [rsi]"
name_456:
	.asciz "pmovzxbw xmm1, xmm2"
name_457:
	.asciz "vpmovzxbw xmm1, xmm2"
name_458:
	.asciz "vpmovzxbw ymm1, xmm2"
name_459:
	.asciz "vpmovzxbw ymm1, [rsi]"
name_460:
	.asciz "pmovzxbd xmm1, xmm2"
name_461:
	.asciz "vpmovzxbd xmm1, xmm2"
name_462:
	.asciz "vpmovzxbd ymm1, xmm2"
name_463:
	.asciz "vpmovzxbd ymm1, [rsi]"
name_464:
	.asciz "pmovzxbq xmm1, xmm2"
name_465:
	.asciz "vpmovzxbq xmm1, xmm2"
name_466:
	.asciz "vpmovzxbq ymm1, xmm2"
name_467:
	.asciz "vpmovzxbq ymm1, [rsi]"
name_468:
	.asciz "pmovzxwd xmm1, xmm2"
name_469:
	.asciz "vpmovzxwd xmm1, xmm2"
name_470:
	.asciz "vpmovzxwd ymm1, xmm2"
name_471:
	.asciz "vpmovzxwd ymm1, [rsi]"
name_472:
	.asciz "pmovzxwq xmm1, xmm2"
name_473:
	.asciz "vpmovzxwq xmm1, xmm2"
name_474:
	.asciz "vpmovzxwq ymm1, xmm2"
name_475:
	.asciz "vpmovzxwq ymm1, [rsi]"
name_476:
	.asciz "pmovzxdq xmm1, xmm2"
name_477:
	.asciz "vpmovzxdq xmm1, xmm2"
name_478:
	.asciz "vpmovzxdq ymm1, xmm2"
name_479:
	.asciz "vpmovzxdq ymm1, [rsi]"
name_480:
	.asciz "pmovsxbw xmm1, xmm2"
name_481:
	.asciz "vpmovsxbw xmm1, xmm2"
name_482:
	.asciz "vpmovsxbw ymm1, xmm2"
name_483:
	.asciz "vpmovsxbw ymm1, [rsi]"
name_484:
	.asciz "pmovsxbd xmm1, xmm2"
name_485:
	.asciz "vpmovsxbd xmm1, xmm2"
name_486:
	.asciz "vpmovsxbd ymm1, xmm2"
name_487:
	.asciz "vpmovsxbd ymm1, [rsi]"
name_488:
	.asciz "pmovsxbq xmm1, xmm2"
name_489:
	.asciz "vpmovsxbq xmm1, xmm2"
name_490:
	.asciz "vpmovsxbq ymm1, xmm2"
name_491:
	.asciz "vpmovsxbq ymm1, [rsi]"
name_492:
	.asciz "pmovsxwd xmm1, xmm2"
name_493:
	.asciz "vpmovsxwd xmm1, xmm2"
name_494:
	.asciz "vpmovsxwd ymm1, xmm2"
name_495:
	.asciz "vpmovsxwd ymm1, [rsi]"
name_496:
	.asciz "pmovsxwq xmm1, xmm2"
name_497:
	.asciz "vpmovsxwq xmm1, xmm2"
name_498:
	.asciz "vpmovsxwq ymm1, xmm2"
name_499:
	.asciz "vpmovsxwq ymm1, [rsi]"
name_500:
	.asciz "pmovsxdq xmm1, xmm2"
name_501:
	.asciz "vpmovsxdq xmm1, xmm2"
name_502:
	.asciz "vpmovsxdq ymm1, xmm2"
name_503:
	.asciz "vpmovsxdq ymm1, [rsi]"
name_504:
	.asciz "psllw xmm1, 3"
name_505:
	.asciz "vpsllw xmm1, xmm2, 3"
name_506:
	.asciz "vpsllw ymm1, ymm2, 3"
name_507:
	.asciz "psllw xmm1, 40"
name_508:
	.asciz "vpsllw xmm1, xmm2, 40"
name_509:
	.asciz "vpsllw ymm1, ymm2, 40"
name_510:
	.asciz "psllw xmm1, xmm5"
name_511:
	.asciz "vpsllw ymm1, ymm2, xmm5"
name_512:
	.asciz "vpsllw ymm1, ymm2, [rsi]"
name_513:
	.asciz "pslld xmm1, 3"
name_514:
	.asciz "vpslld xmm1, xmm2, 3"
name_515:
	.asciz "vpslld ymm1, ymm2, 3"
name_516:
	.asciz "pslld xmm1, 40"
name_517:
	.asciz "vpslld xmm1, xmm2, 40"
name_518:
	.asciz "vpslld ymm1, ymm2, 40"
name_519:
	.asciz "pslld xmm1, xmm5"
name_520:
	.asciz "vpslld ymm1, ymm2, xmm5"
name_521:
	.asciz "vpslld ymm1, ymm2, [rsi]"
name_522:
	.asciz "psllq xmm1, 3"
name_523:
	.asciz "vpsllq xmm1, xmm2, 3"
name_524:
	.asciz "vpsllq ymm1, ymm2, 3"
name_525:
	.asciz "psllq xmm1, 40"
name_526:
	.asciz "vpsllq xmm1, xmm2, 40"
name_527:
	.asciz "vpsllq ymm1, ymm2, 40"
name_528:
	.asciz "psllq xmm1, xmm5"
name_529:
	.asciz "vpsllq ymm1, ymm2, xmm5"
name_530:
	.asciz "vpsllq ymm1, ymm2, [rsi]"
name_531:
	.asciz "psrlw xmm1, 3"
name_532:
	.asciz "vpsrlw xmm1, xmm2, 3"
name_533:
	.asciz "vpsrlw ymm1, ymm2, 3"
name_534:
	.asciz "psrlw xmm1, 40"
name_535:
	.asciz "vpsrlw xmm1, xmm2, 40"
name_536:
	.asciz "vpsrlw ymm1, ymm2, 40"
name_537:
	.asciz "psrlw xmm1, xmm5"
name_538:
	.asciz "vpsrlw ymm1, ymm2, xmm5"
name_539:
	.asciz "vpsrlw ymm1, ymm2, [rsi]"
name_540:
	.asciz "psrld xmm1, 3"
name_541:
	.asciz "vpsrld xmm1, xmm2, 3"
name_542:
	.asciz "vpsrld ymm1, ymm2, 3"
name_543:
	.asciz "psrld xmm1, 40"
name_544:
	.asciz "vpsrld xmm1, xmm2, 40"
name_545:
	.asciz "vpsrld ymm1, ymm2, 40"
name_546:
	.asciz "psrld xmm1, xmm5"
name_547:
	.asciz "vpsrld ymm1, ymm2, xmm5"
name_548:
	.asciz "vpsrld ymm1, ymm2, [rsi]"
name_549:
	.asciz "psrlq xmm1, 3"
name_550:
	.asciz "vpsrlq xmm1, xmm2, 3"
name_551:
	.asciz "vpsrlq ymm1, ymm2, 3"
name_552:
	.asciz "psrlq xmm1, 40"
name_553:
	.asciz "vpsrlq xmm1, xmm2, 40"
name_554:
	.asciz "vpsrlq ymm1, ymm2, 40"
name_555:
	.asciz "psrlq xmm1, xmm5"
name_556:
	.asciz "vpsrlq ymm1, ymm2, xmm5"
name_557:
	.asciz "vpsrlq ymm1, ymm2, [rsi]"
name_558:
	.asciz "psraw xmm1, 3"
name_559:
	.asciz "vpsraw xmm1, xmm2, 3"
name_560:
	.asciz "vpsraw ymm1, ymm2, 3"
name_561:
	.asciz "psraw xmm1, 40"
name_562:
	.asciz "vpsraw xmm1, xmm2, 40"
name_563:
	.asciz "vpsraw ymm1, ymm2, 40"
name_564:
	.asciz "psraw xmm1, xmm5"
name_565:
	.asciz "vpsraw ymm1, ymm2, xmm5"
name_566:
	.asciz "vpsraw ymm1, ymm2, [rsi]"
name_567:
	.asciz "psrad xmm1, 3"
name_568:
	.asciz "vpsrad xmm1, xmm2, 3"
name_569:
	.asciz "vpsrad ymm1, ymm2, 3"
name_570:
	.asciz "psrad xmm1, 40"
name_571:
	.asciz "vpsrad xmm1, xmm2, 40"
name_572:
	.asciz "vpsrad ymm1, ymm2, 40"
name_573:
	.asciz "psrad xmm1, xmm5"
name_574:
	.asciz "vpsrad ymm1, ymm2, xmm5"
name_575:
	.asciz "vpsrad ymm1, ymm2, [rsi]"
name_576:
	.asciz "pslldq xmm1, 3"
name_577:
	.asciz "vpslldq xmm1, xmm2, 3"
name_578:
	.asciz "vpslldq ymm1, ymm2, 3"
name_579:
	.asciz "pslldq xmm1, 15"
name_580:
	.asciz "vpslldq xmm1, xmm2, 15"
name_581:
	.asciz "vpslldq ymm1, ymm2, 15"
name_582:
	.asciz "pslldq xmm1, 20"
name_583:
	.asciz "vpslldq xmm1, xmm2, 20"
name_584:
	.asciz "vpslldq ymm1, ymm2, 20"
name_585:
	.asciz "psrldq xmm1, 3"
name_586:
	.asciz "vpsrldq xmm1, xmm2, 3"
name_587:
	.asciz "vpsrldq ymm1, ymm2, 3"
name_588:
	.asciz "psrldq xmm1, 15"
name_589:
	.asciz "vpsrldq xmm1, xmm2, 15"
name_590:
	.asciz "vpsrldq ymm1, ymm2, 15"
name_591:
	.asciz "psrldq xmm1, 20"
name_592:
	.asciz "vpsrldq xmm1, xmm2, 20"
name_593:
	.asciz "vpsrldq ymm1, ymm2, 20"
name_594:
	.asciz "vpsllvd xmm1, xmm2, xmm4"
name_595:
	.asciz "vpsllvd ymm1, ymm2, ymm4"
name_596:
	.asciz "vpsllvd ymm1, ymm2, [rsi]"
name_597:
	.asciz "vpsllvq xmm1, xmm2, xmm4"
name_598:
	.asciz "vpsllvq ymm1, ymm2, ymm4"
name_599:
	.asciz "vpsllvq ymm1, ymm2, [rsi]"
name_600:
	.asciz "vpsrlvd xmm1, xmm2, xmm4"
name_601:
	.asciz "vpsrlvd ymm1, ymm2, ymm4"
name_602:
	.asciz "vpsrlvd ymm1, ymm2, [rsi]"
name_603:
	.asciz "vpsrlvq xmm1, xmm2, xmm4"
name_604:
	.asciz "vpsrlvq ymm1, ymm2, ymm4"
name_605:
	.asciz "vpsrlvq ymm1, ymm2, [rsi]"
name_606:
	.asciz "vpsravd xmm1, xmm2, xmm4"
name_607:
	.asciz "vpsravd ymm1, ymm2, ymm4"
name_608:
	.asciz "vpsravd ymm1, ymm2, [rsi]"
name_609:
	.asciz "pshufd xmm1, xmm2, 0x1b"
name_610:
	.asciz "vpshufd xmm1, xmm2, 0x1b"
name_611:
	.asciz "vpshufd ymm1, ymm2, 0x72"
name_612:
	.asciz "vpshufd ymm1, [rsi], 0x72"
name_613:
	.asciz "pshuflw xmm1, xmm2, 0x1b"
name_614:
	.asciz "vpshuflw xmm1, xmm2, 0x1b"
name_615:
	.asciz "vpshuflw ymm1, ymm2, 0x72"
name_616:
	.asciz "vpshuflw ymm1, [rsi], 0x72"
name_617:
	.asciz "pshufhw xmm1, xmm2, 0x1b"
name_618:
	.asciz "vpshufhw xmm1, xmm2, 0x1b"
name_619:
	.asciz "vpshufhw ymm1, ymm2, 0x72"
name_620:
	.asciz "vpshufhw ymm1, [rsi], 0x72"
name_621:
	.asciz "palignr xmm1, xmm2, 3"
name_622:
	.asciz "vpalignr xmm1, xmm2, xmm3, 3"
name_623:
	.asciz "vpalignr ymm1, ymm2, ymm3, 3"
name_624:
	.asciz "palignr xmm1, xmm2, 17"
name_625:
	.asciz "vpalignr xmm1, xmm2, xmm3, 17"
name_626:
	.asciz "vpalignr ymm1, ymm2, ymm3, 17"
name_627:
	.asciz "palignr xmm1, xmm2, 40"
name_628:
	.asciz "vpalignr xmm1, xmm2, xmm3, 40"
name_629:
	.asciz "vpalignr ymm1, ymm2, ymm3, 40"
name_630:
	.asciz "vpalignr ymm1, ymm2, [rsi], 5"
name_631:
	.asciz "pblendw xmm1, xmm2, 0xa5"
name_632:
	.asciz "vpblendw xmm1, xmm2, xmm3, 5"
name_633:
	.asciz "vpblendw ymm1, ymm2, ymm3, 0xa5"
name_634:
	.asciz "blendps xmm1, xmm2, 5"
name_635:
	.asciz "vblendps xmm1, xmm2, xmm3, 5"
name_636:
	.asciz "vblendps ymm1, ymm2, ymm3, 0xa5"
name_637:
	.asciz "blendpd xmm1, xmm2, 5"
name_638:
	.asciz "vblendpd xmm1, xmm2, xmm3, 5"
name_639:
	.asciz "vblendpd ymm1, ymm2, ymm3, 5"
name_640:
	.asciz "vpblendd xmm1, xmm2, xmm3, 5"
name_641:
	.asciz "vpblendd ymm1, ymm2, ymm3, 0xa5"
name_642:
	.asciz "vpblendd ymm1, ymm2, [rsi], 0x3c"
name_643:
	.asciz "pblendvb xmm1, xmm2, xmm0"
name_644:
	.asciz "blendvps xmm1, xmm2, xmm0"
name_645:
	.asciz "blendvpd xmm1, xmm2, xmm0"
name_646:
	.asciz "vpblendvb xmm1, xmm2, xmm3, xmm4"
name_647:
	.asciz "vpblendvb ymm1, ymm2, ymm3, ymm4"
name_648:
	.asciz "vpblendvb ymm1, ymm2, [rsi], ymm4"
name_649:
	.asciz "vblendvps xmm1, xmm2, xmm3, xmm4"
name_650:
	.asciz "vblendvps ymm1, ymm2, ymm3, ymm4"
name_651:
	.asciz "vblendvps ymm1, ymm2, [rsi], ymm4"
name_652:
	.asciz "vblendvpd xmm1, xmm2, xmm3, xmm4"
name_653:
	.asciz "vblendvpd ymm1, ymm2, ymm3, ymm4"
name_654:
	.asciz "vblendvpd ymm1, ymm2, [rsi], ymm4"
name_655:
	.asciz "shufps xmm1, xmm2, 0x1b"
name_656:
	.asciz "vshufps xmm1, xmm2, xmm3, 0x1b"
name_657:
	.asciz "vshufps ymm1, ymm2, ymm3, 0x72"
name_658:
	.asciz "shufpd xmm1, xmm2, 0x1b"
name_659:
	.asciz "vshufpd xmm1, xmm2, xmm3, 0x1b"
name_660:
	.asciz "vshufpd ymm1, ymm2, ymm3, 0x72"
name_661:
	.asciz "unpcklps xmm1, xmm2"
name_662:
	.asciz "vunpcklps xmm1, xmm2, xmm3"
name_663:
	.asciz "vunpcklps ymm1, ymm2, ymm3"
name_664:
	.asciz "unpcklpd xmm1, xmm2"
name_665:
	.asciz "vunpcklpd xmm1, xmm2, xmm3"
name_666:
	.asciz "vunpcklpd ymm1, ymm2, ymm3"
name_667:
	.asciz "unpckhps xmm1, xmm2"
name_668:
	.asciz "vunpckhps xmm1, xmm2, xmm3"
name_669:
	.asciz "vunpckhps ymm1, ymm2, ymm3"
name_670:
	.asciz "unpckhpd xmm1, xmm2"
name_671:
	.asciz "vunpckhpd xmm1, xmm2, xmm3"
name_672:
	.asciz "vunpckhpd ymm1, ymm2, ymm3"
name_673:
	.asciz "andps xmm1, xmm2"
name_674:
	.asciz "vandps xmm1, xmm2, xmm3"
name_675:
	.asciz "vandps ymm1, ymm2, ymm3"
name_676:
	.asciz "vandps ymm1, ymm2, [rsi]"
name_677:
	.asciz "andpd xmm1, xmm2"
name_678:
	.asciz "vandpd xmm1, xmm2, xmm3"
name_679:
	.asciz "vandpd ymm1, ymm2, ymm3"
name_680:
	.asciz "vandpd ymm1, ymm2, [rsi]"
name_681:
	.asciz "orps xmm1, xmm2"
name_682:
	.asciz "vorps xmm1, xmm2, xmm3"
name_683:
	.asciz "vorps ymm1, ymm2, ymm3"
name_684:
	.asciz "vorps ymm1, ymm2, [rsi]"
name_685:
	.asciz "orpd xmm1, xmm2"
name_686:
	.asciz "vorpd xmm1, xmm2, xmm3"
name_687:
	.asciz "vorpd ymm1, ymm2, ymm3"
name_688:
	.asciz "vorpd ymm1, ymm2, [rsi]"
name_689:
	.asciz "xorps xmm1, xmm2"
name_690:
	.asciz "vxorps xmm1, xmm2, xmm3"
name_691:
	.asciz "vxorps ymm1, ymm2, ymm3"
name_692:
	.asciz "vxorps ymm1, ymm2, [rsi]"
name_693:
	.asciz "xorpd xmm1, xmm2"
name_694:
	.asciz "vxorpd xmm1, xmm2, xmm3"
name_695:
	.asciz "vxorpd ymm1, ymm2, ymm3"
name_696:
	.asciz "vxorpd ymm1, ymm2, [rsi]"
name_697:
	.asciz "andnps xmm1, xmm2"
name_698:
	.asciz "vandnps xmm1, xmm2, xmm3"
name_699:
	.asciz "vandnps ymm1, ymm2, ymm3"
name_700:
	.asciz "vandnps ymm1, ymm2, [rsi]"
name_701:
	.asciz "andnpd xmm1, xmm2"
name_702:
	.asciz "vandnpd xmm1, xmm2, xmm3"
name_703:
	.asciz "vandnpd ymm1, ymm2, ymm3"
name_704:
	.asciz "vandnpd ymm1, ymm2, [rsi]"
name_705:
	.asciz "vpermq ymm1, ymm2, 0x1b"
name_706:
	.asciz "vpermq ymm1, [rsi], 0x72"
name_707:
	.asciz "vpermpd ymm1, ymm2, 0x1b"
name_708:
	.asciz "vpermd ymm1, ymm2, ymm3"
name_709:
	.asciz "vpermd ymm1, ymm2, [rsi]"
name_710:
	.asciz "vpermps ymm1, ymm2, ymm3"
name_711:
	.asciz "vperm2i128 ymm1, ymm2, ymm3, 0x21"
name_712:
	.asciz "vperm2i128 ymm1, ymm2, ymm3, 0x08"
name_713:
	.asciz "vperm2i128 ymm1, ymm2, [rsi], 0x31"
name_714:
	.asciz "vperm2f128 ymm1, ymm2, ymm3, 0x12"
name_715:
	.asciz "vpermilps xmm1, xmm2, 0x1b"
name_716:
	.asciz "vpermilps ymm1, ymm2, 0x72"
name_717:
	.asciz "vpermilps ymm1, ymm2, ymm3"
name_718:
	.asciz "vpermilpd xmm1, xmm2, 1"
name_719:
	.asciz "vpermilpd ymm1, ymm2, 5"
name_720:
	.asciz "vpermilpd ymm1, ymm2, ymm3"
name_721:
	.asciz "vinserti128 ymm1, ymm2, xmm3, 1"
name_722:
	.asciz "vinserti128 ymm1, ymm2, xmm3, 0"
name_723:
	.asciz "vinserti128 ymm1, ymm2, [rsi], 1"
name_724:
	.asciz "vinsertf128 ymm1, ymm2, xmm3, 1"
name_725:
	.asciz "vinsertf128 ymm1, ymm2, [rsi], 0"
name_726:
	.asciz "vextracti128 xmm1, ymm2, 1"
name_727:
	.asciz "vextracti128 xmm1, ymm2, 0"
name_728:
	.asciz "vextracti128 [rdi], ymm2, 1"
name_729:
	.asciz "vextractf128 xmm1, ymm2, 1"
name_730:
	.asciz "vextractf128 [rdi], ymm2, 1"
name_731:
	.asciz "vpbroadcastb xmm1, xmm2"
name_732:
	.asciz "vpbroadcastb ymm1, xmm2"
name_733:
	.asciz "vpbroadcastb ymm1, byte ptr [rsi]"
name_734:
	.asciz "vpbroadcastw xmm1, xmm2"
name_735:
	.asciz "vpbroadcastw ymm1, xmm2"
name_736:
	.asciz "vpbroadcastw ymm1, word ptr [rsi]"
name_737:
	.asciz "vpbroadcastd xmm1, xmm2"
name_738:
	.asciz "vpbroadcastd ymm1, xmm2"
name_739:
	.asciz "vpbroadcastd ymm1, dword ptr [rsi]"
name_740:
	.asciz "vpbroadcastq xmm1, xmm2"
name_741:
	.asciz "vpbroadcastq ymm1, xmm2"
name_742:
	.asciz "vpbroadcastq ymm1, qword ptr [rsi]"
name_743:
	.asciz "vbroadcastss xmm1, xmm2"
name_744:
	.asciz "vbroadcastss ymm1, xmm2"
name_745:
	.asciz "vbroadcastss ymm1, dword ptr [rsi]"
name_746:
	.asciz "vbroadcastsd ymm1, xmm2"
name_747:
	.asciz "vbroadcastsd ymm1, qword ptr [rsi]"
name_748:
	.asciz "vbroadcastf128 ymm1, [rsi]"
name_749:
	.asciz "vbroadcasti128 ymm1, [rsi]"
name_750:
	.asciz "ptest xmm1, xmm2"
name_751:
	.asciz "vptest xmm1, xmm2"
name_752:
	.asciz "vptest ymm1, ymm2"
name_753:
	.asciz "vptest ymm0, ymm0"
name_754:
	.asciz "vptest ymm1, [rsi]"
name_755:
	.asciz "vtestps xmm1, xmm2"
name_756:
	.asciz "vtestps ymm1, ymm2"
name_757:
	.asciz "vtestpd ymm1, ymm2"
name_758:
	.asciz "pmovmskb eax, xmm2"
name_759:
	.asciz "vpmovmskb eax, xmm2"
name_760:
	.asciz "vpmovmskb eax, ymm2"
name_761:
	.asciz "movmskps eax, xmm2"
name_762:
	.asciz "vmovmskps eax, xmm2"
name_763:
	.asciz "vmovmskps eax, ymm2"
name_764:
	.asciz "movmskpd eax, xmm2"
name_765:
	.asciz "vmovmskpd eax, ymm2"
name_766:
	.asciz "vmovd xmm1, eax"
name_767:
	.asciz "vmovd xmm1, dword ptr [rsi]"
name_768:
	.asciz "vmovd eax, xmm2"
name_769:
	.asciz "vmovd dword ptr [rdi], xmm2"
name_770:
	.asciz "vmovq xmm1, rax"
name_771:
	.asciz "vmovq xmm1, qword ptr [rsi]"
name_772:
	.asciz "vmovq rax, xmm2"
name_773:
	.asciz "vmovq qword ptr [rdi], xmm2"
name_774:
	.asciz "vmovq xmm1, xmm2"
name_775:
	.asciz "vmovdqa xmm1, xmm2"
name_776:
	.asciz "vmovdqa ymm1, ymm2"
name_777:
	.asciz "vmovdqa ymm1, [rsi]"
name_778:
	.asciz "vmovdqa [rdi], ymm2"
name_779:
	.asciz "vmovdqu xmm1, [rsi+1]"
name_780:
	.asciz "vmovdqu ymm1, [rsi+1]"
name_781:
	.asciz "vmovdqu [rdi+1], ymm2"
name_782:
	.asciz "vmovdqu [rdi+1], xmm2"
name_783:
	.asciz "vmovaps ymm1, ymm2"
name_784:
	.asciz "vmovaps ymm1, [rsi]"
name_785:
	.asciz "vmovaps [rdi], ymm2"
name_786:
	.asciz "vmovups ymm1, [rsi+1]"
name_787:
	.asciz "vmovups [rdi+1], ymm2"
name_788:
	.asciz "vmovups xmm1, [rsi+1]"
name_789:
	.asciz "vmovapd ymm1, [rsi]"
name_790:
	.asciz "vmovupd ymm1, [rsi+1]"
name_791:
	.asciz "vmovss xmm1, xmm2, xmm3"
name_792:
	.asciz "vmovss xmm1, dword ptr [rsi]"
name_793:
	.asciz "vmovss dword ptr [rdi], xmm2"
name_794:
	.asciz "vmovsd xmm1, xmm2, xmm3"
name_795:
	.asciz "vmovsd xmm1, qword ptr [rsi]"
name_796:
	.asciz "vmovsd qword ptr [rdi], xmm2"
name_797:
	.asciz "vmovhps xmm1, xmm2, qword ptr [rsi]"
name_798:
	.asciz "vmovhps qword ptr [rdi], xmm2"
name_799:
	.asciz "vmovlps xmm1, xmm2, qword ptr [rsi]"
name_800:
	.asciz "vmovlps qword ptr [rdi], xmm2"
name_801:
	.asciz "vmovhpd xmm1, xmm2, qword ptr [rsi]"
name_802:
	.asciz "vmovhpd qword ptr [rdi], xmm2"
name_803:
	.asciz "vmovlpd xmm1, xmm2, qword ptr [rsi]"
name_804:
	.asciz "vmovlpd qword ptr [rdi], xmm2"
name_805:
	.asciz "vmovhlps xmm1, xmm2, xmm3"
name_806:
	.asciz "vmovlhps xmm1, xmm2, xmm3"
name_807:
	.asciz "vmovntdq [rdi], ymm2"
name_808:
	.asciz "vmovntdq [rdi], xmm2"
name_809:
	.asciz "vmovntdqa ymm1, [rsi]"
name_810:
	.asciz "vmovntdqa xmm1, [rsi]"
name_811:
	.asciz "vmovntps [rdi], ymm2"
name_812:
	.asciz "vmovntpd [rdi], ymm2"
name_813:
	.asciz "vlddqu ymm1, [rsi+1]"
name_814:
	.asciz "vlddqu xmm1, [rsi+1]"
name_815:
	.asciz "vmovshdup ymm1, ymm2"
name_816:
	.asciz "vmovshdup xmm1, xmm2"
name_817:
	.asciz "vmovsldup ymm1, ymm2"
name_818:
	.asciz "vmovsldup xmm1, xmm2"
name_819:
	.asciz "vmovddup ymm1, ymm2"
name_820:
	.asciz "vmovddup xmm1, xmm2"
name_821:
	.asciz "movshdup xmm1, xmm2"
name_822:
	.asciz "movsldup xmm1, xmm2"
name_823:
	.asciz "movddup xmm1, xmm2"
name_824:
	.asciz "lddqu xmm1, [rsi+1]"
name_825:
	.asciz "movntdqa xmm1, [rsi]"
name_826:
	.asciz "vpinsrb xmm1, xmm2, eax, 5"
name_827:
	.asciz "vpinsrw xmm1, xmm2, eax, 5"
name_828:
	.asciz "vpinsrd xmm1, xmm2, eax, 2"
name_829:
	.asciz "vpinsrq xmm1, xmm2, rax, 1"
name_830:
	.asciz "vpinsrb xmm1, xmm2, byte ptr [rsi], 15"
name_831:
	.asciz "vpinsrw xmm1, xmm2, word ptr [rsi], 7"
name_832:
	.asciz "vpinsrd xmm1, xmm2, dword ptr [rsi], 3"
name_833:
	.asciz "vpinsrq xmm1, xmm2, qword ptr [rsi], 0"
name_834:
	.asciz "vpextrb eax, xmm2, 5"
name_835:
	.asciz "vpextrw eax, xmm2, 5"
name_836:
	.asciz "vpextrd eax, xmm2, 2"
name_837:
	.asciz "vpextrq rax, xmm2, 1"
name_838:
	.asciz "vpextrb byte ptr [rdi], xmm2, 15"
name_839:
	.asciz "vpextrw word ptr [rdi], xmm2, 7"
name_840:
	.asciz "vpextrd dword ptr [rdi], xmm2, 3"
name_841:
	.asciz "vpextrq qword ptr [rdi], xmm2, 0"
name_842:
	.asciz "vextractps eax, xmm2, 2"
name_843:
	.asciz "vextractps dword ptr [rdi], xmm2, 1"
name_844:
	.asciz "vinsertps xmm1, xmm2, xmm3, 0x9c"
name_845:
	.asciz "vinsertps xmm1, xmm2, dword ptr [rsi], 0x13"
name_846:
	.asciz "pinsrb xmm1, eax, 5"
name_847:
	.asciz "pinsrd xmm1, eax, 2"
name_848:
	.asciz "pinsrq xmm1, rax, 1"
name_849:
	.asciz "pinsrw xmm1, eax, 5"
name_850:
	.asciz "pextrb eax, xmm2, 5"
name_851:
	.asciz "pextrd eax, xmm2, 2"
name_852:
	.asciz "pextrq rax, xmm2, 1"
name_853:
	.asciz "pextrw eax, xmm2, 5"
name_854:
	.asciz "insertps xmm1, xmm2, 0x9c"
name_855:
	.asciz "extractps eax, xmm2, 2"
name_856:
	.asciz "vmaskmovps ymm1, ymm2, [rsi]"
name_857:
	.asciz "vmaskmovps xmm1, xmm2, [rsi]"
name_858:
	.asciz "vmaskmovpd ymm1, ymm4, [rsi]"
name_859:
	.asciz "vmaskmovps [rdi], ymm2, ymm3"
name_860:
	.asciz "vmaskmovpd [rdi], ymm4, ymm3"
name_861:
	.asciz "vpmaskmovd ymm1, ymm2, [rsi]"
name_862:
	.asciz "vpmaskmovd xmm1, xmm2, [rsi]"
name_863:
	.asciz "vpmaskmovq ymm1, ymm4, [rsi]"
name_864:
	.asciz "vpmaskmovq xmm1, xmm4, [rsi]"
name_865:
	.asciz "vpmaskmovd [rdi], ymm2, ymm3"
name_866:
	.asciz "vpmaskmovq [rdi], ymm4, ymm3"
name_867:
	.asciz "vpmaskmovd [rdi], xmm2, xmm3"
name_868:
	.asciz "vzeroupper"
name_869:
	.asciz "vzeroall"
name_870:
	.asciz "addps xmm9, xmm10"
name_871:
	.asciz "vaddps xmm1, xmm9, xmm10"
name_872:
	.asciz "vaddps ymm1, ymm9, ymm10"
name_873:
	.asciz "vaddps ymm1, ymm9, [rsi+0]"
name_874:
	.asciz "addpd xmm13, xmm14"
name_875:
	.asciz "vaddpd xmm1, xmm13, xmm14"
name_876:
	.asciz "vaddpd ymm1, ymm13, ymm14"
name_877:
	.asciz "addss xmm9, xmm10"
name_878:
	.asciz "vaddss xmm1, xmm9, xmm10"
name_879:
	.asciz "addsd xmm13, xmm14"
name_880:
	.asciz "vaddsd xmm1, xmm13, xmm14"
name_881:
	.asciz "subps xmm9, xmm10"
name_882:
	.asciz "vsubps xmm1, xmm9, xmm10"
name_883:
	.asciz "vsubps ymm1, ymm9, ymm10"
name_884:
	.asciz "vsubps ymm1, ymm9, [rsi+0]"
name_885:
	.asciz "subpd xmm13, xmm14"
name_886:
	.asciz "vsubpd xmm1, xmm13, xmm14"
name_887:
	.asciz "vsubpd ymm1, ymm13, ymm14"
name_888:
	.asciz "subss xmm9, xmm10"
name_889:
	.asciz "vsubss xmm1, xmm9, xmm10"
name_890:
	.asciz "subsd xmm13, xmm14"
name_891:
	.asciz "vsubsd xmm1, xmm13, xmm14"
name_892:
	.asciz "mulps xmm9, xmm10"
name_893:
	.asciz "vmulps xmm1, xmm9, xmm10"
name_894:
	.asciz "vmulps ymm1, ymm9, ymm10"
name_895:
	.asciz "vmulps ymm1, ymm9, [rsi+0]"
name_896:
	.asciz "mulpd xmm13, xmm14"
name_897:
	.asciz "vmulpd xmm1, xmm13, xmm14"
name_898:
	.asciz "vmulpd ymm1, ymm13, ymm14"
name_899:
	.asciz "mulss xmm9, xmm10"
name_900:
	.asciz "vmulss xmm1, xmm9, xmm10"
name_901:
	.asciz "mulsd xmm13, xmm14"
name_902:
	.asciz "vmulsd xmm1, xmm13, xmm14"
name_903:
	.asciz "divps xmm9, xmm10"
name_904:
	.asciz "vdivps xmm1, xmm9, xmm10"
name_905:
	.asciz "vdivps ymm1, ymm9, ymm10"
name_906:
	.asciz "vdivps ymm1, ymm9, [rsi+0]"
name_907:
	.asciz "divpd xmm13, xmm14"
name_908:
	.asciz "vdivpd xmm1, xmm13, xmm14"
name_909:
	.asciz "vdivpd ymm1, ymm13, ymm14"
name_910:
	.asciz "divss xmm9, xmm10"
name_911:
	.asciz "vdivss xmm1, xmm9, xmm10"
name_912:
	.asciz "divsd xmm13, xmm14"
name_913:
	.asciz "vdivsd xmm1, xmm13, xmm14"
name_914:
	.asciz "minps xmm9, xmm10"
name_915:
	.asciz "vminps xmm1, xmm9, xmm10"
name_916:
	.asciz "vminps ymm1, ymm9, ymm10"
name_917:
	.asciz "vminps ymm1, ymm9, [rsi+0]"
name_918:
	.asciz "minpd xmm13, xmm14"
name_919:
	.asciz "vminpd xmm1, xmm13, xmm14"
name_920:
	.asciz "vminpd ymm1, ymm13, ymm14"
name_921:
	.asciz "minss xmm9, xmm10"
name_922:
	.asciz "vminss xmm1, xmm9, xmm10"
name_923:
	.asciz "minsd xmm13, xmm14"
name_924:
	.asciz "vminsd xmm1, xmm13, xmm14"
name_925:
	.asciz "maxps xmm9, xmm10"
name_926:
	.asciz "vmaxps xmm1, xmm9, xmm10"
name_927:
	.asciz "vmaxps ymm1, ymm9, ymm10"
name_928:
	.asciz "vmaxps ymm1, ymm9, [rsi+0]"
name_929:
	.asciz "maxpd xmm13, xmm14"
name_930:
	.asciz "vmaxpd xmm1, xmm13, xmm14"
name_931:
	.asciz "vmaxpd ymm1, ymm13, ymm14"
name_932:
	.asciz "maxss xmm9, xmm10"
name_933:
	.asciz "vmaxss xmm1, xmm9, xmm10"
name_934:
	.asciz "maxsd xmm13, xmm14"
name_935:
	.asciz "vmaxsd xmm1, xmm13, xmm14"
name_936:
	.asciz "addsubps xmm9, xmm10"
name_937:
	.asciz "vaddsubps xmm1, xmm9, xmm10"
name_938:
	.asciz "vaddsubps ymm1, ymm9, ymm10"
name_939:
	.asciz "vaddsubps ymm1, ymm9, [rsi+0]"
name_940:
	.asciz "haddps xmm9, xmm10"
name_941:
	.asciz "vhaddps xmm1, xmm9, xmm10"
name_942:
	.asciz "vhaddps ymm1, ymm9, ymm10"
name_943:
	.asciz "vhaddps ymm1, ymm9, [rsi+0]"
name_944:
	.asciz "hsubps xmm9, xmm10"
name_945:
	.asciz "vhsubps xmm1, xmm9, xmm10"
name_946:
	.asciz "vhsubps ymm1, ymm9, ymm10"
name_947:
	.asciz "vhsubps ymm1, ymm9, [rsi+0]"
name_948:
	.asciz "addsubpd xmm13, xmm14"
name_949:
	.asciz "vaddsubpd xmm1, xmm13, xmm14"
name_950:
	.asciz "vaddsubpd ymm1, ymm13, ymm14"
name_951:
	.asciz "haddpd xmm13, xmm14"
name_952:
	.asciz "vhaddpd xmm1, xmm13, xmm14"
name_953:
	.asciz "vhaddpd ymm1, ymm13, ymm14"
name_954:
	.asciz "hsubpd xmm13, xmm14"
name_955:
	.asciz "vhsubpd xmm1, xmm13, xmm14"
name_956:
	.asciz "vhsubpd ymm1, ymm13, ymm14"
name_957:
	.asciz "sqrtps xmm1, xmm9"
name_958:
	.asciz "vsqrtps xmm1, xmm9"
name_959:
	.asciz "vsqrtps ymm1, ymm9"
name_960:
	.asciz "vsqrtpd xmm1, xmm13"
name_961:
	.asciz "vsqrtpd ymm1, ymm13"
name_962:
	.asciz "vsqrtss xmm1, xmm2, xmm9"
name_963:
	.asciz "vsqrtsd xmm1, xmm2, xmm13"
name_964:
	.asciz "vcmpps ymm1, ymm9, ymm10, 0"
name_965:
	.asciz "vcmppd ymm1, ymm13, ymm14, 0"
name_966:
	.asciz "vcmpss xmm1, xmm9, xmm11, 0"
name_967:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 0"
name_968:
	.asciz "vcmpps ymm1, ymm9, ymm10, 1"
name_969:
	.asciz "vcmppd ymm1, ymm13, ymm14, 1"
name_970:
	.asciz "vcmpss xmm1, xmm9, xmm11, 1"
name_971:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 1"
name_972:
	.asciz "vcmpps ymm1, ymm9, ymm10, 2"
name_973:
	.asciz "vcmppd ymm1, ymm13, ymm14, 2"
name_974:
	.asciz "vcmpss xmm1, xmm9, xmm11, 2"
name_975:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 2"
name_976:
	.asciz "vcmpps ymm1, ymm9, ymm10, 3"
name_977:
	.asciz "vcmppd ymm1, ymm13, ymm14, 3"
name_978:
	.asciz "vcmpss xmm1, xmm9, xmm11, 3"
name_979:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 3"
name_980:
	.asciz "vcmpps ymm1, ymm9, ymm10, 4"
name_981:
	.asciz "vcmppd ymm1, ymm13, ymm14, 4"
name_982:
	.asciz "vcmpss xmm1, xmm9, xmm11, 4"
name_983:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 4"
name_984:
	.asciz "vcmpps ymm1, ymm9, ymm10, 5"
name_985:
	.asciz "vcmppd ymm1, ymm13, ymm14, 5"
name_986:
	.asciz "vcmpss xmm1, xmm9, xmm11, 5"
name_987:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 5"
name_988:
	.asciz "vcmpps ymm1, ymm9, ymm10, 6"
name_989:
	.asciz "vcmppd ymm1, ymm13, ymm14, 6"
name_990:
	.asciz "vcmpss xmm1, xmm9, xmm11, 6"
name_991:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 6"
name_992:
	.asciz "vcmpps ymm1, ymm9, ymm10, 7"
name_993:
	.asciz "vcmppd ymm1, ymm13, ymm14, 7"
name_994:
	.asciz "vcmpss xmm1, xmm9, xmm11, 7"
name_995:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 7"
name_996:
	.asciz "vcmpps ymm1, ymm9, ymm10, 8"
name_997:
	.asciz "vcmppd ymm1, ymm13, ymm14, 8"
name_998:
	.asciz "vcmpss xmm1, xmm9, xmm11, 8"
name_999:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 8"
name_1000:
	.asciz "vcmpps ymm1, ymm9, ymm10, 9"
name_1001:
	.asciz "vcmppd ymm1, ymm13, ymm14, 9"
name_1002:
	.asciz "vcmpss xmm1, xmm9, xmm11, 9"
name_1003:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 9"
name_1004:
	.asciz "vcmpps ymm1, ymm9, ymm10, 10"
name_1005:
	.asciz "vcmppd ymm1, ymm13, ymm14, 10"
name_1006:
	.asciz "vcmpss xmm1, xmm9, xmm11, 10"
name_1007:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 10"
name_1008:
	.asciz "vcmpps ymm1, ymm9, ymm10, 11"
name_1009:
	.asciz "vcmppd ymm1, ymm13, ymm14, 11"
name_1010:
	.asciz "vcmpss xmm1, xmm9, xmm11, 11"
name_1011:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 11"
name_1012:
	.asciz "vcmpps ymm1, ymm9, ymm10, 12"
name_1013:
	.asciz "vcmppd ymm1, ymm13, ymm14, 12"
name_1014:
	.asciz "vcmpss xmm1, xmm9, xmm11, 12"
name_1015:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 12"
name_1016:
	.asciz "vcmpps ymm1, ymm9, ymm10, 13"
name_1017:
	.asciz "vcmppd ymm1, ymm13, ymm14, 13"
name_1018:
	.asciz "vcmpss xmm1, xmm9, xmm11, 13"
name_1019:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 13"
name_1020:
	.asciz "vcmpps ymm1, ymm9, ymm10, 14"
name_1021:
	.asciz "vcmppd ymm1, ymm13, ymm14, 14"
name_1022:
	.asciz "vcmpss xmm1, xmm9, xmm11, 14"
name_1023:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 14"
name_1024:
	.asciz "vcmpps ymm1, ymm9, ymm10, 15"
name_1025:
	.asciz "vcmppd ymm1, ymm13, ymm14, 15"
name_1026:
	.asciz "vcmpss xmm1, xmm9, xmm11, 15"
name_1027:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 15"
name_1028:
	.asciz "vcmpps ymm1, ymm9, ymm10, 16"
name_1029:
	.asciz "vcmppd ymm1, ymm13, ymm14, 16"
name_1030:
	.asciz "vcmpss xmm1, xmm9, xmm11, 16"
name_1031:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 16"
name_1032:
	.asciz "vcmpps ymm1, ymm9, ymm10, 17"
name_1033:
	.asciz "vcmppd ymm1, ymm13, ymm14, 17"
name_1034:
	.asciz "vcmpss xmm1, xmm9, xmm11, 17"
name_1035:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 17"
name_1036:
	.asciz "vcmpps ymm1, ymm9, ymm10, 18"
name_1037:
	.asciz "vcmppd ymm1, ymm13, ymm14, 18"
name_1038:
	.asciz "vcmpss xmm1, xmm9, xmm11, 18"
name_1039:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 18"
name_1040:
	.asciz "vcmpps ymm1, ymm9, ymm10, 19"
name_1041:
	.asciz "vcmppd ymm1, ymm13, ymm14, 19"
name_1042:
	.asciz "vcmpss xmm1, xmm9, xmm11, 19"
name_1043:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 19"
name_1044:
	.asciz "vcmpps ymm1, ymm9, ymm10, 20"
name_1045:
	.asciz "vcmppd ymm1, ymm13, ymm14, 20"
name_1046:
	.asciz "vcmpss xmm1, xmm9, xmm11, 20"
name_1047:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 20"
name_1048:
	.asciz "vcmpps ymm1, ymm9, ymm10, 21"
name_1049:
	.asciz "vcmppd ymm1, ymm13, ymm14, 21"
name_1050:
	.asciz "vcmpss xmm1, xmm9, xmm11, 21"
name_1051:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 21"
name_1052:
	.asciz "vcmpps ymm1, ymm9, ymm10, 22"
name_1053:
	.asciz "vcmppd ymm1, ymm13, ymm14, 22"
name_1054:
	.asciz "vcmpss xmm1, xmm9, xmm11, 22"
name_1055:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 22"
name_1056:
	.asciz "vcmpps ymm1, ymm9, ymm10, 23"
name_1057:
	.asciz "vcmppd ymm1, ymm13, ymm14, 23"
name_1058:
	.asciz "vcmpss xmm1, xmm9, xmm11, 23"
name_1059:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 23"
name_1060:
	.asciz "vcmpps ymm1, ymm9, ymm10, 24"
name_1061:
	.asciz "vcmppd ymm1, ymm13, ymm14, 24"
name_1062:
	.asciz "vcmpss xmm1, xmm9, xmm11, 24"
name_1063:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 24"
name_1064:
	.asciz "vcmpps ymm1, ymm9, ymm10, 25"
name_1065:
	.asciz "vcmppd ymm1, ymm13, ymm14, 25"
name_1066:
	.asciz "vcmpss xmm1, xmm9, xmm11, 25"
name_1067:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 25"
name_1068:
	.asciz "vcmpps ymm1, ymm9, ymm10, 26"
name_1069:
	.asciz "vcmppd ymm1, ymm13, ymm14, 26"
name_1070:
	.asciz "vcmpss xmm1, xmm9, xmm11, 26"
name_1071:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 26"
name_1072:
	.asciz "vcmpps ymm1, ymm9, ymm10, 27"
name_1073:
	.asciz "vcmppd ymm1, ymm13, ymm14, 27"
name_1074:
	.asciz "vcmpss xmm1, xmm9, xmm11, 27"
name_1075:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 27"
name_1076:
	.asciz "vcmpps ymm1, ymm9, ymm10, 28"
name_1077:
	.asciz "vcmppd ymm1, ymm13, ymm14, 28"
name_1078:
	.asciz "vcmpss xmm1, xmm9, xmm11, 28"
name_1079:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 28"
name_1080:
	.asciz "vcmpps ymm1, ymm9, ymm10, 29"
name_1081:
	.asciz "vcmppd ymm1, ymm13, ymm14, 29"
name_1082:
	.asciz "vcmpss xmm1, xmm9, xmm11, 29"
name_1083:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 29"
name_1084:
	.asciz "vcmpps ymm1, ymm9, ymm10, 30"
name_1085:
	.asciz "vcmppd ymm1, ymm13, ymm14, 30"
name_1086:
	.asciz "vcmpss xmm1, xmm9, xmm11, 30"
name_1087:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 30"
name_1088:
	.asciz "vcmpps ymm1, ymm9, ymm10, 31"
name_1089:
	.asciz "vcmppd ymm1, ymm13, ymm14, 31"
name_1090:
	.asciz "vcmpss xmm1, xmm9, xmm11, 31"
name_1091:
	.asciz "vcmpsd xmm1, xmm13, xmm15, 31"
name_1092:
	.asciz "vcmpps xmm1, xmm9, xmm10, 1"
name_1093:
	.asciz "vcmppd xmm1, xmm13, xmm14, 2"
name_1094:
	.asciz "cmpps xmm9, xmm10, 1"
name_1095:
	.asciz "cmpsd xmm13, xmm14, 2"
name_1096:
	.asciz "comiss xmm9, xmm10"
name_1097:
	.asciz "vcomiss xmm9, xmm10"
name_1098:
	.asciz "vucomiss xmm9, xmm11"
name_1099:
	.asciz "vcomisd xmm13, xmm14"
name_1100:
	.asciz "vucomisd xmm13, xmm15"
name_1101:
	.asciz "vroundps ymm1, ymm9, 0"
name_1102:
	.asciz "vroundps xmm1, xmm9, 0"
name_1103:
	.asciz "vroundpd ymm1, ymm13, 0"
name_1104:
	.asciz "vroundss xmm1, xmm2, xmm9, 0"
name_1105:
	.asciz "vroundsd xmm1, xmm2, xmm13, 0"
name_1106:
	.asciz "roundps xmm1, xmm9, 0"
name_1107:
	.asciz "roundsd xmm1, xmm13, 0"
name_1108:
	.asciz "vroundps ymm1, ymm9, 1"
name_1109:
	.asciz "vroundps xmm1, xmm9, 1"
name_1110:
	.asciz "vroundpd ymm1, ymm13, 1"
name_1111:
	.asciz "vroundss xmm1, xmm2, xmm9, 1"
name_1112:
	.asciz "vroundsd xmm1, xmm2, xmm13, 1"
name_1113:
	.asciz "roundps xmm1, xmm9, 1"
name_1114:
	.asciz "roundsd xmm1, xmm13, 1"
name_1115:
	.asciz "vroundps ymm1, ymm9, 2"
name_1116:
	.asciz "vroundps xmm1, xmm9, 2"
name_1117:
	.asciz "vroundpd ymm1, ymm13, 2"
name_1118:
	.asciz "vroundss xmm1, xmm2, xmm9, 2"
name_1119:
	.asciz "vroundsd xmm1, xmm2, xmm13, 2"
name_1120:
	.asciz "roundps xmm1, xmm9, 2"
name_1121:
	.asciz "roundsd xmm1, xmm13, 2"
name_1122:
	.asciz "vroundps ymm1, ymm9, 3"
name_1123:
	.asciz "vroundps xmm1, xmm9, 3"
name_1124:
	.asciz "vroundpd ymm1, ymm13, 3"
name_1125:
	.asciz "vroundss xmm1, xmm2, xmm9, 3"
name_1126:
	.asciz "vroundsd xmm1, xmm2, xmm13, 3"
name_1127:
	.asciz "roundps xmm1, xmm9, 3"
name_1128:
	.asciz "roundsd xmm1, xmm13, 3"
name_1129:
	.asciz "vroundps ymm1, ymm9, 4"
name_1130:
	.asciz "vroundps xmm1, xmm9, 4"
name_1131:
	.asciz "vroundpd ymm1, ymm13, 4"
name_1132:
	.asciz "vroundss xmm1, xmm2, xmm9, 4"
name_1133:
	.asciz "vroundsd xmm1, xmm2, xmm13, 4"
name_1134:
	.asciz "roundps xmm1, xmm9, 4"
name_1135:
	.asciz "roundsd xmm1, xmm13, 4"
name_1136:
	.asciz "vroundps ymm1, ymm9, 9"
name_1137:
	.asciz "vroundps xmm1, xmm9, 9"
name_1138:
	.asciz "vroundpd ymm1, ymm13, 9"
name_1139:
	.asciz "vroundss xmm1, xmm2, xmm9, 9"
name_1140:
	.asciz "vroundsd xmm1, xmm2, xmm13, 9"
name_1141:
	.asciz "roundps xmm1, xmm9, 9"
name_1142:
	.asciz "roundsd xmm1, xmm13, 9"
name_1143:
	.asciz "vcvtdq2ps ymm1, ymm2"
name_1144:
	.asciz "vcvtdq2ps xmm1, xmm2"
name_1145:
	.asciz "vcvtdq2pd ymm1, xmm2"
name_1146:
	.asciz "vcvtdq2pd xmm1, xmm2"
name_1147:
	.asciz "vcvtps2dq ymm1, ymm9"
name_1148:
	.asciz "vcvtps2dq xmm1, xmm9"
name_1149:
	.asciz "vcvttps2dq ymm1, ymm9"
name_1150:
	.asciz "vcvttps2dq xmm1, xmm9"
name_1151:
	.asciz "vcvtpd2dq xmm1, ymm13"
name_1152:
	.asciz "vcvtpd2dq xmm1, xmm13"
name_1153:
	.asciz "vcvttpd2dq xmm1, ymm13"
name_1154:
	.asciz "vcvttpd2dq xmm1, xmm13"
name_1155:
	.asciz "vcvtps2pd ymm1, xmm9"
name_1156:
	.asciz "vcvtps2pd xmm1, xmm9"
name_1157:
	.asciz "vcvtpd2ps xmm1, ymm13"
name_1158:
	.asciz "vcvtpd2ps xmm1, xmm13"
name_1159:
	.asciz "vcvtsi2ss xmm1, xmm2, eax"
name_1160:
	.asciz "vcvtsi2sd xmm1, xmm2, rax"
name_1161:
	.asciz "vcvtss2sd xmm1, xmm2, xmm9"
name_1162:
	.asciz "vcvtsd2ss xmm1, xmm2, xmm13"
name_1163:
	.asciz "vcvtsd2si rax, xmm13"
name_1164:
	.asciz "vcvttsd2si rax, xmm13"
name_1165:
	.asciz "vcvtss2si eax, xmm9"
name_1166:
	.asciz "vcvttss2si eax, xmm9"
name_1167:
	.asciz "vcvtph2ps ymm1, xmm2"
name_1168:
	.asciz "vcvtph2ps xmm1, xmm2"
name_1169:
	.asciz "vcvtps2ph xmm1, ymm9, 0"
name_1170:
	.asciz "vcvtps2ph xmm1, xmm9, 0"
name_1171:
	.asciz "vdppd xmm1, xmm13, xmm14, 0x31"
name_1172:
	.asciz "vdpps xmm1, xmm9, xmm10, 0xf1"
name_1173:
	.asciz "vdpps ymm1, ymm9, ymm10, 0x7f"
name_1174:
	.asciz "vmpsadbw xmm1, xmm2, xmm3, 5"
name_1175:
	.asciz "vmpsadbw ymm1, ymm2, ymm3, 0x2d"
name_1176:
	.asciz "vphminposuw xmm1, xmm2"
name_1177:
	.asciz "phminposuw xmm1, xmm2"
name_1178:
	.asciz "mpsadbw xmm1, xmm2, 5"
name_1179:
	.asciz "dppd xmm13, xmm14, 0x31"
name_1180:
	.asciz "dpps xmm9, xmm10, 0xf1"
name_1181:
	.asciz "vfmadd132ps ymm9, ymm10, ymm11"
name_1182:
	.asciz "vfmadd132ps xmm9, xmm10, xmm11"
name_1183:
	.asciz "vfmadd132pd ymm13, ymm14, ymm15"
name_1184:
	.asciz "vfmadd132pd xmm13, xmm14, xmm15"
name_1185:
	.asciz "vfmadd132ss xmm9, xmm10, xmm11"
name_1186:
	.asciz "vfmadd132sd xmm13, xmm14, xmm15"
name_1187:
	.asciz "vfmadd213ps ymm9, ymm10, ymm11"
name_1188:
	.asciz "vfmadd213ps xmm9, xmm10, xmm11"
name_1189:
	.asciz "vfmadd213pd ymm13, ymm14, ymm15"
name_1190:
	.asciz "vfmadd213pd xmm13, xmm14, xmm15"
name_1191:
	.asciz "vfmadd213ss xmm9, xmm10, xmm11"
name_1192:
	.asciz "vfmadd213sd xmm13, xmm14, xmm15"
name_1193:
	.asciz "vfmadd231ps ymm9, ymm10, ymm11"
name_1194:
	.asciz "vfmadd231ps xmm9, xmm10, xmm11"
name_1195:
	.asciz "vfmadd231pd ymm13, ymm14, ymm15"
name_1196:
	.asciz "vfmadd231pd xmm13, xmm14, xmm15"
name_1197:
	.asciz "vfmadd231ss xmm9, xmm10, xmm11"
name_1198:
	.asciz "vfmadd231sd xmm13, xmm14, xmm15"
name_1199:
	.asciz "vfmsub132ps ymm9, ymm10, ymm11"
name_1200:
	.asciz "vfmsub132ps xmm9, xmm10, xmm11"
name_1201:
	.asciz "vfmsub132pd ymm13, ymm14, ymm15"
name_1202:
	.asciz "vfmsub132pd xmm13, xmm14, xmm15"
name_1203:
	.asciz "vfmsub132ss xmm9, xmm10, xmm11"
name_1204:
	.asciz "vfmsub132sd xmm13, xmm14, xmm15"
name_1205:
	.asciz "vfmsub213ps ymm9, ymm10, ymm11"
name_1206:
	.asciz "vfmsub213ps xmm9, xmm10, xmm11"
name_1207:
	.asciz "vfmsub213pd ymm13, ymm14, ymm15"
name_1208:
	.asciz "vfmsub213pd xmm13, xmm14, xmm15"
name_1209:
	.asciz "vfmsub213ss xmm9, xmm10, xmm11"
name_1210:
	.asciz "vfmsub213sd xmm13, xmm14, xmm15"
name_1211:
	.asciz "vfmsub231ps ymm9, ymm10, ymm11"
name_1212:
	.asciz "vfmsub231ps xmm9, xmm10, xmm11"
name_1213:
	.asciz "vfmsub231pd ymm13, ymm14, ymm15"
name_1214:
	.asciz "vfmsub231pd xmm13, xmm14, xmm15"
name_1215:
	.asciz "vfmsub231ss xmm9, xmm10, xmm11"
name_1216:
	.asciz "vfmsub231sd xmm13, xmm14, xmm15"
name_1217:
	.asciz "vfnmadd132ps ymm9, ymm10, ymm11"
name_1218:
	.asciz "vfnmadd132ps xmm9, xmm10, xmm11"
name_1219:
	.asciz "vfnmadd132pd ymm13, ymm14, ymm15"
name_1220:
	.asciz "vfnmadd132pd xmm13, xmm14, xmm15"
name_1221:
	.asciz "vfnmadd132ss xmm9, xmm10, xmm11"
name_1222:
	.asciz "vfnmadd132sd xmm13, xmm14, xmm15"
name_1223:
	.asciz "vfnmadd213ps ymm9, ymm10, ymm11"
name_1224:
	.asciz "vfnmadd213ps xmm9, xmm10, xmm11"
name_1225:
	.asciz "vfnmadd213pd ymm13, ymm14, ymm15"
name_1226:
	.asciz "vfnmadd213pd xmm13, xmm14, xmm15"
name_1227:
	.asciz "vfnmadd213ss xmm9, xmm10, xmm11"
name_1228:
	.asciz "vfnmadd213sd xmm13, xmm14, xmm15"
name_1229:
	.asciz "vfnmadd231ps ymm9, ymm10, ymm11"
name_1230:
	.asciz "vfnmadd231ps xmm9, xmm10, xmm11"
name_1231:
	.asciz "vfnmadd231pd ymm13, ymm14, ymm15"
name_1232:
	.asciz "vfnmadd231pd xmm13, xmm14, xmm15"
name_1233:
	.asciz "vfnmadd231ss xmm9, xmm10, xmm11"
name_1234:
	.asciz "vfnmadd231sd xmm13, xmm14, xmm15"
name_1235:
	.asciz "vfnmsub132ps ymm9, ymm10, ymm11"
name_1236:
	.asciz "vfnmsub132ps xmm9, xmm10, xmm11"
name_1237:
	.asciz "vfnmsub132pd ymm13, ymm14, ymm15"
name_1238:
	.asciz "vfnmsub132pd xmm13, xmm14, xmm15"
name_1239:
	.asciz "vfnmsub132ss xmm9, xmm10, xmm11"
name_1240:
	.asciz "vfnmsub132sd xmm13, xmm14, xmm15"
name_1241:
	.asciz "vfnmsub213ps ymm9, ymm10, ymm11"
name_1242:
	.asciz "vfnmsub213ps xmm9, xmm10, xmm11"
name_1243:
	.asciz "vfnmsub213pd ymm13, ymm14, ymm15"
name_1244:
	.asciz "vfnmsub213pd xmm13, xmm14, xmm15"
name_1245:
	.asciz "vfnmsub213ss xmm9, xmm10, xmm11"
name_1246:
	.asciz "vfnmsub213sd xmm13, xmm14, xmm15"
name_1247:
	.asciz "vfnmsub231ps ymm9, ymm10, ymm11"
name_1248:
	.asciz "vfnmsub231ps xmm9, xmm10, xmm11"
name_1249:
	.asciz "vfnmsub231pd ymm13, ymm14, ymm15"
name_1250:
	.asciz "vfnmsub231pd xmm13, xmm14, xmm15"
name_1251:
	.asciz "vfnmsub231ss xmm9, xmm10, xmm11"
name_1252:
	.asciz "vfnmsub231sd xmm13, xmm14, xmm15"
name_1253:
	.asciz "vfmaddsub132ps ymm9, ymm10, ymm11"
name_1254:
	.asciz "vfmaddsub132pd ymm13, ymm14, ymm15"
name_1255:
	.asciz "vfmaddsub213ps ymm9, ymm10, ymm11"
name_1256:
	.asciz "vfmaddsub213pd ymm13, ymm14, ymm15"
name_1257:
	.asciz "vfmaddsub231ps ymm9, ymm10, ymm11"
name_1258:
	.asciz "vfmaddsub231pd ymm13, ymm14, ymm15"
name_1259:
	.asciz "vfmsubadd132ps ymm9, ymm10, ymm11"
name_1260:
	.asciz "vfmsubadd132pd ymm13, ymm14, ymm15"
name_1261:
	.asciz "vfmsubadd213ps ymm9, ymm10, ymm11"
name_1262:
	.asciz "vfmsubadd213pd ymm13, ymm14, ymm15"
name_1263:
	.asciz "vfmsubadd231ps ymm9, ymm10, ymm11"
name_1264:
	.asciz "vfmsubadd231pd ymm13, ymm14, ymm15"
name_1265:
	.asciz "andn r8, rax, rbx"
name_1266:
	.asciz "andn r8d, eax, ebx"
name_1267:
	.asciz "bextr r8, rax, rcx"
name_1268:
	.asciz "blsi r8, rax"
name_1269:
	.asciz "blsmsk r8, rax"
name_1270:
	.asciz "blsr r8, rax"
name_1271:
	.asciz "bzhi r8, rax, rcx"
name_1272:
	.asciz "mulx r8, r9, rax"
name_1273:
	.asciz "pdep r8, rax, rbx"
name_1274:
	.asciz "pext r8, rax, rbx"
name_1275:
	.asciz "rorx r8, rax, 13"
name_1276:
	.asciz "rorx r8d, eax, 13"
name_1277:
	.asciz "sarx r8, rax, rcx"
name_1278:
	.asciz "shlx r8, rax, rcx"
name_1279:
	.asciz "shrx r8, rax, rcx"
name_1280:
	.asciz "shlx r8d, eax, ecx"
name_1281:
	.asciz "shrx r8d, eax, ecx"
name_1282:
	.asciz "sarx r8d, eax, ecx"
name_1283:
	.asciz "tzcnt r8, rax"
name_1284:
	.asciz "tzcnt r8d, ebx"
name_1285:
	.asciz "lzcnt r8, rax"
name_1286:
	.asciz "lzcnt r8d, ebx"
name_1287:
	.asciz "popcnt r8, rax"
name_1288:
	.asciz "movbe r8, [rsi]"
name_1289:
	.asciz "movbe r8d, [rsi]"
name_1290:
	.asciz "movbe [rdi], rax"
name_1291:
	.asciz "movbe [rdi], eax"
name_1292:
	.asciz "crc32 r8d, al"
name_1293:
	.asciz "crc32 r8, rax"
name_1294:
	.asciz "crc32 r8d, eax"
name_1295:
	.asciz "cmpxchg16b [rdi]"
name_1296:
	.asciz "lzcnt rax, rax"
name_1297:
	.asciz "lzcnt ebx, ebx"
name_1298:
	.asciz "tzcnt rax, rax"
name_1299:
	.asciz "tzcnt ebx, ebx"
name_1300:
	.asciz "mov rax, rsi; lzcnt rax, [rax]"
name_1301:
	.asciz "mov rax, rsi; tzcnt rax, [rax]"
name_1302:
	.asciz "blsi rax, rax"
name_1303:
	.asciz "blsr rax, rax"
name_1304:
	.asciz "blsmsk rax, rax"
name_1305:
	.asciz "mulx rax, rbx, rax"
name_1306:
	.asciz "pdep rax, rax, rax"
name_1307:
	.asciz "pext rax, rax, rax"
name_1308:
	.asciz "rorx rax, rax, 5"
name_1309:
	.asciz "andn rax, rax, rbx"
name_1310:
	.asciz "bzhi rax, rax, rcx"
name_1311:
	.asciz "shlx rax, rax, rax"
name_1312:
	.asciz "popcnt rax, rax"
name_1313:
	.asciz "movbe rax, [rsi]"
name_1314:
	.asciz "pcmpistri xmm2, xmm3, 0"
name_1315:
	.asciz "pcmpistri xmm2, xmm3, 0x1a"
name_1316:
	.asciz "pcmpistrm xmm2, xmm3, 0x40"
name_1317:
	.asciz "pcmpestri xmm2, xmm3, 0x0c"
name_1318:
	.asciz "pcmpestrm xmm2, xmm3, 0x40"
name_1319:
	.asciz "vpcmpistri xmm2, xmm3, 0"
name_1320:
	.asciz "vpcmpistri xmm6, xmm7, 0x08"
name_1321:
	.asciz "vpcmpistri xmm6, xmm7, 0x1a"
name_1322:
	.asciz "vpcmpistrm xmm6, xmm7, 0x40"
name_1323:
	.asciz "vpcmpestri xmm6, xmm7, 0x0c"
name_1324:
	.asciz "vpcmpestrm xmm6, xmm7, 0x40"
name_1325:
	.asciz "mov eax, 6; xor edx, edx; lea r8, [rip + xarea]; xsave [r8]; vpxor ymm1, ymm1, ymm1; vpxor xmm9, xmm9, xmm9; xrstor [r8]; xor r8d, r8d; mov eax, 0x33; xor edx, edx"
name_1326:
	.asciz "vpgatherdd ymm1, [r10 + ymm5*4], ymm6"
name_1327:
	.asciz "vpgatherdq ymm1, [r10 + xmm5*2], ymm6"
name_1328:
	.asciz "vpgatherqq ymm1, [r10 + ymm5*2], ymm6"
name_1329:
	.asciz "vgatherdps ymm1, [r10 + ymm5*4], ymm6"
name_1330:
	.asciz "vgatherdpd ymm1, [r10 + xmm5*2], ymm6"
name_1331:
	.asciz "vpgatherdd xmm1, [r10 + xmm5*4], xmm6"
.data
.globl cases
.p2align 3
cases:
	.quad case_0, name_0, 2261
	.quad case_1, name_1, 2261
	.quad case_2, name_2, 2261
	.quad case_3, name_3, 2261
	.quad case_4, name_4, 2261
	.quad case_5, name_5, 2261
	.quad case_6, name_6, 2261
	.quad case_7, name_7, 2261
	.quad case_8, name_8, 2261
	.quad case_9, name_9, 2261
	.quad case_10, name_10, 2261
	.quad case_11, name_11, 2261
	.quad case_12, name_12, 2261
	.quad case_13, name_13, 2261
	.quad case_14, name_14, 2261
	.quad case_15, name_15, 2261
	.quad case_16, name_16, 2261
	.quad case_17, name_17, 2261
	.quad case_18, name_18, 2261
	.quad case_19, name_19, 2261
	.quad case_20, name_20, 2261
	.quad case_21, name_21, 2261
	.quad case_22, name_22, 2261
	.quad case_23, name_23, 2261
	.quad case_24, name_24, 2261
	.quad case_25, name_25, 2261
	.quad case_26, name_26, 2261
	.quad case_27, name_27, 2261
	.quad case_28, name_28, 2261
	.quad case_29, name_29, 2261
	.quad case_30, name_30, 2261
	.quad case_31, name_31, 2261
	.quad case_32, name_32, 2261
	.quad case_33, name_33, 2261
	.quad case_34, name_34, 2261
	.quad case_35, name_35, 2261
	.quad case_36, name_36, 2261
	.quad case_37, name_37, 2261
	.quad case_38, name_38, 2261
	.quad case_39, name_39, 2261
	.quad case_40, name_40, 2261
	.quad case_41, name_41, 2261
	.quad case_42, name_42, 2261
	.quad case_43, name_43, 2261
	.quad case_44, name_44, 2261
	.quad case_45, name_45, 2261
	.quad case_46, name_46, 2261
	.quad case_47, name_47, 2261
	.quad case_48, name_48, 2261
	.quad case_49, name_49, 2261
	.quad case_50, name_50, 2261
	.quad case_51, name_51, 2261
	.quad case_52, name_52, 2261
	.quad case_53, name_53, 2261
	.quad case_54, name_54, 2261
	.quad case_55, name_55, 2261
	.quad case_56, name_56, 2261
	.quad case_57, name_57, 2261
	.quad case_58, name_58, 2261
	.quad case_59, name_59, 2261
	.quad case_60, name_60, 2261
	.quad case_61, name_61, 2261
	.quad case_62, name_62, 2261
	.quad case_63, name_63, 2261
	.quad case_64, name_64, 2261
	.quad case_65, name_65, 2261
	.quad case_66, name_66, 2261
	.quad case_67, name_67, 2261
	.quad case_68, name_68, 2261
	.quad case_69, name_69, 2261
	.quad case_70, name_70, 2261
	.quad case_71, name_71, 2261
	.quad case_72, name_72, 2261
	.quad case_73, name_73, 2261
	.quad case_74, name_74, 2261
	.quad case_75, name_75, 2261
	.quad case_76, name_76, 2261
	.quad case_77, name_77, 2261
	.quad case_78, name_78, 2261
	.quad case_79, name_79, 2261
	.quad case_80, name_80, 2261
	.quad case_81, name_81, 2261
	.quad case_82, name_82, 2261
	.quad case_83, name_83, 2261
	.quad case_84, name_84, 2261
	.quad case_85, name_85, 2261
	.quad case_86, name_86, 2261
	.quad case_87, name_87, 2261
	.quad case_88, name_88, 2261
	.quad case_89, name_89, 2261
	.quad case_90, name_90, 2261
	.quad case_91, name_91, 2261
	.quad case_92, name_92, 2261
	.quad case_93, name_93, 2261
	.quad case_94, name_94, 2261
	.quad case_95, name_95, 2261
	.quad case_96, name_96, 2261
	.quad case_97, name_97, 2261
	.quad case_98, name_98, 2261
	.quad case_99, name_99, 2261
	.quad case_100, name_100, 2261
	.quad case_101, name_101, 2261
	.quad case_102, name_102, 2261
	.quad case_103, name_103, 2261
	.quad case_104, name_104, 2261
	.quad case_105, name_105, 2261
	.quad case_106, name_106, 2261
	.quad case_107, name_107, 2261
	.quad case_108, name_108, 2261
	.quad case_109, name_109, 2261
	.quad case_110, name_110, 2261
	.quad case_111, name_111, 2261
	.quad case_112, name_112, 2261
	.quad case_113, name_113, 2261
	.quad case_114, name_114, 2261
	.quad case_115, name_115, 2261
	.quad case_116, name_116, 2261
	.quad case_117, name_117, 2261
	.quad case_118, name_118, 2261
	.quad case_119, name_119, 2261
	.quad case_120, name_120, 2261
	.quad case_121, name_121, 2261
	.quad case_122, name_122, 2261
	.quad case_123, name_123, 2261
	.quad case_124, name_124, 2261
	.quad case_125, name_125, 2261
	.quad case_126, name_126, 2261
	.quad case_127, name_127, 2261
	.quad case_128, name_128, 2261
	.quad case_129, name_129, 2261
	.quad case_130, name_130, 2261
	.quad case_131, name_131, 2261
	.quad case_132, name_132, 2261
	.quad case_133, name_133, 2261
	.quad case_134, name_134, 2261
	.quad case_135, name_135, 2261
	.quad case_136, name_136, 2261
	.quad case_137, name_137, 2261
	.quad case_138, name_138, 2261
	.quad case_139, name_139, 2261
	.quad case_140, name_140, 2261
	.quad case_141, name_141, 2261
	.quad case_142, name_142, 2261
	.quad case_143, name_143, 2261
	.quad case_144, name_144, 2261
	.quad case_145, name_145, 2261
	.quad case_146, name_146, 2261
	.quad case_147, name_147, 2261
	.quad case_148, name_148, 2261
	.quad case_149, name_149, 2261
	.quad case_150, name_150, 2261
	.quad case_151, name_151, 2261
	.quad case_152, name_152, 2261
	.quad case_153, name_153, 2261
	.quad case_154, name_154, 2261
	.quad case_155, name_155, 2261
	.quad case_156, name_156, 2261
	.quad case_157, name_157, 2261
	.quad case_158, name_158, 2261
	.quad case_159, name_159, 2261
	.quad case_160, name_160, 2261
	.quad case_161, name_161, 2261
	.quad case_162, name_162, 2261
	.quad case_163, name_163, 2261
	.quad case_164, name_164, 2261
	.quad case_165, name_165, 2261
	.quad case_166, name_166, 2261
	.quad case_167, name_167, 2261
	.quad case_168, name_168, 2261
	.quad case_169, name_169, 2261
	.quad case_170, name_170, 2261
	.quad case_171, name_171, 2261
	.quad case_172, name_172, 2261
	.quad case_173, name_173, 2261
	.quad case_174, name_174, 2261
	.quad case_175, name_175, 2261
	.quad case_176, name_176, 2261
	.quad case_177, name_177, 2261
	.quad case_178, name_178, 2261
	.quad case_179, name_179, 2261
	.quad case_180, name_180, 2261
	.quad case_181, name_181, 2261
	.quad case_182, name_182, 2261
	.quad case_183, name_183, 2261
	.quad case_184, name_184, 2261
	.quad case_185, name_185, 2261
	.quad case_186, name_186, 2261
	.quad case_187, name_187, 2261
	.quad case_188, name_188, 2261
	.quad case_189, name_189, 2261
	.quad case_190, name_190, 2261
	.quad case_191, name_191, 2261
	.quad case_192, name_192, 2261
	.quad case_193, name_193, 2261
	.quad case_194, name_194, 2261
	.quad case_195, name_195, 2261
	.quad case_196, name_196, 2261
	.quad case_197, name_197, 2261
	.quad case_198, name_198, 2261
	.quad case_199, name_199, 2261
	.quad case_200, name_200, 2261
	.quad case_201, name_201, 2261
	.quad case_202, name_202, 2261
	.quad case_203, name_203, 2261
	.quad case_204, name_204, 2261
	.quad case_205, name_205, 2261
	.quad case_206, name_206, 2261
	.quad case_207, name_207, 2261
	.quad case_208, name_208, 2261
	.quad case_209, name_209, 2261
	.quad case_210, name_210, 2261
	.quad case_211, name_211, 2261
	.quad case_212, name_212, 2261
	.quad case_213, name_213, 2261
	.quad case_214, name_214, 2261
	.quad case_215, name_215, 2261
	.quad case_216, name_216, 2261
	.quad case_217, name_217, 2261
	.quad case_218, name_218, 2261
	.quad case_219, name_219, 2261
	.quad case_220, name_220, 2261
	.quad case_221, name_221, 2261
	.quad case_222, name_222, 2261
	.quad case_223, name_223, 2261
	.quad case_224, name_224, 2261
	.quad case_225, name_225, 2261
	.quad case_226, name_226, 2261
	.quad case_227, name_227, 2261
	.quad case_228, name_228, 2261
	.quad case_229, name_229, 2261
	.quad case_230, name_230, 2261
	.quad case_231, name_231, 2261
	.quad case_232, name_232, 2261
	.quad case_233, name_233, 2261
	.quad case_234, name_234, 2261
	.quad case_235, name_235, 2261
	.quad case_236, name_236, 2261
	.quad case_237, name_237, 2261
	.quad case_238, name_238, 2261
	.quad case_239, name_239, 2261
	.quad case_240, name_240, 2261
	.quad case_241, name_241, 2261
	.quad case_242, name_242, 2261
	.quad case_243, name_243, 2261
	.quad case_244, name_244, 2261
	.quad case_245, name_245, 2261
	.quad case_246, name_246, 2261
	.quad case_247, name_247, 2261
	.quad case_248, name_248, 2261
	.quad case_249, name_249, 2261
	.quad case_250, name_250, 2261
	.quad case_251, name_251, 2261
	.quad case_252, name_252, 2261
	.quad case_253, name_253, 2261
	.quad case_254, name_254, 2261
	.quad case_255, name_255, 2261
	.quad case_256, name_256, 2261
	.quad case_257, name_257, 2261
	.quad case_258, name_258, 2261
	.quad case_259, name_259, 2261
	.quad case_260, name_260, 2261
	.quad case_261, name_261, 2261
	.quad case_262, name_262, 2261
	.quad case_263, name_263, 2261
	.quad case_264, name_264, 2261
	.quad case_265, name_265, 2261
	.quad case_266, name_266, 2261
	.quad case_267, name_267, 2261
	.quad case_268, name_268, 2261
	.quad case_269, name_269, 2261
	.quad case_270, name_270, 2261
	.quad case_271, name_271, 2261
	.quad case_272, name_272, 2261
	.quad case_273, name_273, 2261
	.quad case_274, name_274, 2261
	.quad case_275, name_275, 2261
	.quad case_276, name_276, 2261
	.quad case_277, name_277, 2261
	.quad case_278, name_278, 2261
	.quad case_279, name_279, 2261
	.quad case_280, name_280, 2261
	.quad case_281, name_281, 2261
	.quad case_282, name_282, 2261
	.quad case_283, name_283, 2261
	.quad case_284, name_284, 2261
	.quad case_285, name_285, 2261
	.quad case_286, name_286, 2261
	.quad case_287, name_287, 2261
	.quad case_288, name_288, 2261
	.quad case_289, name_289, 2261
	.quad case_290, name_290, 2261
	.quad case_291, name_291, 2261
	.quad case_292, name_292, 2261
	.quad case_293, name_293, 2261
	.quad case_294, name_294, 2261
	.quad case_295, name_295, 2261
	.quad case_296, name_296, 2261
	.quad case_297, name_297, 2261
	.quad case_298, name_298, 2261
	.quad case_299, name_299, 2261
	.quad case_300, name_300, 2261
	.quad case_301, name_301, 2261
	.quad case_302, name_302, 2261
	.quad case_303, name_303, 2261
	.quad case_304, name_304, 2261
	.quad case_305, name_305, 2261
	.quad case_306, name_306, 2261
	.quad case_307, name_307, 2261
	.quad case_308, name_308, 2261
	.quad case_309, name_309, 2261
	.quad case_310, name_310, 2261
	.quad case_311, name_311, 2261
	.quad case_312, name_312, 2261
	.quad case_313, name_313, 2261
	.quad case_314, name_314, 2261
	.quad case_315, name_315, 2261
	.quad case_316, name_316, 2261
	.quad case_317, name_317, 2261
	.quad case_318, name_318, 2261
	.quad case_319, name_319, 2261
	.quad case_320, name_320, 2261
	.quad case_321, name_321, 2261
	.quad case_322, name_322, 2261
	.quad case_323, name_323, 2261
	.quad case_324, name_324, 2261
	.quad case_325, name_325, 2261
	.quad case_326, name_326, 2261
	.quad case_327, name_327, 2261
	.quad case_328, name_328, 2261
	.quad case_329, name_329, 2261
	.quad case_330, name_330, 2261
	.quad case_331, name_331, 2261
	.quad case_332, name_332, 2261
	.quad case_333, name_333, 2261
	.quad case_334, name_334, 2261
	.quad case_335, name_335, 2261
	.quad case_336, name_336, 2261
	.quad case_337, name_337, 2261
	.quad case_338, name_338, 2261
	.quad case_339, name_339, 2261
	.quad case_340, name_340, 2261
	.quad case_341, name_341, 2261
	.quad case_342, name_342, 2261
	.quad case_343, name_343, 2261
	.quad case_344, name_344, 2261
	.quad case_345, name_345, 2261
	.quad case_346, name_346, 2261
	.quad case_347, name_347, 2261
	.quad case_348, name_348, 2261
	.quad case_349, name_349, 2261
	.quad case_350, name_350, 2261
	.quad case_351, name_351, 2261
	.quad case_352, name_352, 2261
	.quad case_353, name_353, 2261
	.quad case_354, name_354, 2261
	.quad case_355, name_355, 2261
	.quad case_356, name_356, 2261
	.quad case_357, name_357, 2261
	.quad case_358, name_358, 2261
	.quad case_359, name_359, 2261
	.quad case_360, name_360, 2261
	.quad case_361, name_361, 2261
	.quad case_362, name_362, 2261
	.quad case_363, name_363, 2261
	.quad case_364, name_364, 2261
	.quad case_365, name_365, 2261
	.quad case_366, name_366, 2261
	.quad case_367, name_367, 2261
	.quad case_368, name_368, 2261
	.quad case_369, name_369, 2261
	.quad case_370, name_370, 2261
	.quad case_371, name_371, 2261
	.quad case_372, name_372, 2261
	.quad case_373, name_373, 2261
	.quad case_374, name_374, 2261
	.quad case_375, name_375, 2261
	.quad case_376, name_376, 2261
	.quad case_377, name_377, 2261
	.quad case_378, name_378, 2261
	.quad case_379, name_379, 2261
	.quad case_380, name_380, 2261
	.quad case_381, name_381, 2261
	.quad case_382, name_382, 2261
	.quad case_383, name_383, 2261
	.quad case_384, name_384, 2261
	.quad case_385, name_385, 2261
	.quad case_386, name_386, 2261
	.quad case_387, name_387, 2261
	.quad case_388, name_388, 2261
	.quad case_389, name_389, 2261
	.quad case_390, name_390, 2261
	.quad case_391, name_391, 2261
	.quad case_392, name_392, 2261
	.quad case_393, name_393, 2261
	.quad case_394, name_394, 2261
	.quad case_395, name_395, 2261
	.quad case_396, name_396, 2261
	.quad case_397, name_397, 2261
	.quad case_398, name_398, 2261
	.quad case_399, name_399, 2261
	.quad case_400, name_400, 2261
	.quad case_401, name_401, 2261
	.quad case_402, name_402, 2261
	.quad case_403, name_403, 2261
	.quad case_404, name_404, 2261
	.quad case_405, name_405, 2261
	.quad case_406, name_406, 2261
	.quad case_407, name_407, 2261
	.quad case_408, name_408, 2261
	.quad case_409, name_409, 2261
	.quad case_410, name_410, 2261
	.quad case_411, name_411, 2261
	.quad case_412, name_412, 2261
	.quad case_413, name_413, 2261
	.quad case_414, name_414, 2261
	.quad case_415, name_415, 2261
	.quad case_416, name_416, 2261
	.quad case_417, name_417, 2261
	.quad case_418, name_418, 2261
	.quad case_419, name_419, 2261
	.quad case_420, name_420, 2261
	.quad case_421, name_421, 2261
	.quad case_422, name_422, 2261
	.quad case_423, name_423, 2261
	.quad case_424, name_424, 2261
	.quad case_425, name_425, 2261
	.quad case_426, name_426, 2261
	.quad case_427, name_427, 2261
	.quad case_428, name_428, 2261
	.quad case_429, name_429, 2261
	.quad case_430, name_430, 2261
	.quad case_431, name_431, 2261
	.quad case_432, name_432, 2261
	.quad case_433, name_433, 2261
	.quad case_434, name_434, 2261
	.quad case_435, name_435, 2261
	.quad case_436, name_436, 2261
	.quad case_437, name_437, 2261
	.quad case_438, name_438, 2261
	.quad case_439, name_439, 2261
	.quad case_440, name_440, 2261
	.quad case_441, name_441, 2261
	.quad case_442, name_442, 2261
	.quad case_443, name_443, 2261
	.quad case_444, name_444, 2261
	.quad case_445, name_445, 2261
	.quad case_446, name_446, 2261
	.quad case_447, name_447, 2261
	.quad case_448, name_448, 2261
	.quad case_449, name_449, 2261
	.quad case_450, name_450, 2261
	.quad case_451, name_451, 2261
	.quad case_452, name_452, 2261
	.quad case_453, name_453, 2261
	.quad case_454, name_454, 2261
	.quad case_455, name_455, 2261
	.quad case_456, name_456, 2261
	.quad case_457, name_457, 2261
	.quad case_458, name_458, 2261
	.quad case_459, name_459, 2261
	.quad case_460, name_460, 2261
	.quad case_461, name_461, 2261
	.quad case_462, name_462, 2261
	.quad case_463, name_463, 2261
	.quad case_464, name_464, 2261
	.quad case_465, name_465, 2261
	.quad case_466, name_466, 2261
	.quad case_467, name_467, 2261
	.quad case_468, name_468, 2261
	.quad case_469, name_469, 2261
	.quad case_470, name_470, 2261
	.quad case_471, name_471, 2261
	.quad case_472, name_472, 2261
	.quad case_473, name_473, 2261
	.quad case_474, name_474, 2261
	.quad case_475, name_475, 2261
	.quad case_476, name_476, 2261
	.quad case_477, name_477, 2261
	.quad case_478, name_478, 2261
	.quad case_479, name_479, 2261
	.quad case_480, name_480, 2261
	.quad case_481, name_481, 2261
	.quad case_482, name_482, 2261
	.quad case_483, name_483, 2261
	.quad case_484, name_484, 2261
	.quad case_485, name_485, 2261
	.quad case_486, name_486, 2261
	.quad case_487, name_487, 2261
	.quad case_488, name_488, 2261
	.quad case_489, name_489, 2261
	.quad case_490, name_490, 2261
	.quad case_491, name_491, 2261
	.quad case_492, name_492, 2261
	.quad case_493, name_493, 2261
	.quad case_494, name_494, 2261
	.quad case_495, name_495, 2261
	.quad case_496, name_496, 2261
	.quad case_497, name_497, 2261
	.quad case_498, name_498, 2261
	.quad case_499, name_499, 2261
	.quad case_500, name_500, 2261
	.quad case_501, name_501, 2261
	.quad case_502, name_502, 2261
	.quad case_503, name_503, 2261
	.quad case_504, name_504, 2261
	.quad case_505, name_505, 2261
	.quad case_506, name_506, 2261
	.quad case_507, name_507, 2261
	.quad case_508, name_508, 2261
	.quad case_509, name_509, 2261
	.quad case_510, name_510, 2261
	.quad case_511, name_511, 2261
	.quad case_512, name_512, 2261
	.quad case_513, name_513, 2261
	.quad case_514, name_514, 2261
	.quad case_515, name_515, 2261
	.quad case_516, name_516, 2261
	.quad case_517, name_517, 2261
	.quad case_518, name_518, 2261
	.quad case_519, name_519, 2261
	.quad case_520, name_520, 2261
	.quad case_521, name_521, 2261
	.quad case_522, name_522, 2261
	.quad case_523, name_523, 2261
	.quad case_524, name_524, 2261
	.quad case_525, name_525, 2261
	.quad case_526, name_526, 2261
	.quad case_527, name_527, 2261
	.quad case_528, name_528, 2261
	.quad case_529, name_529, 2261
	.quad case_530, name_530, 2261
	.quad case_531, name_531, 2261
	.quad case_532, name_532, 2261
	.quad case_533, name_533, 2261
	.quad case_534, name_534, 2261
	.quad case_535, name_535, 2261
	.quad case_536, name_536, 2261
	.quad case_537, name_537, 2261
	.quad case_538, name_538, 2261
	.quad case_539, name_539, 2261
	.quad case_540, name_540, 2261
	.quad case_541, name_541, 2261
	.quad case_542, name_542, 2261
	.quad case_543, name_543, 2261
	.quad case_544, name_544, 2261
	.quad case_545, name_545, 2261
	.quad case_546, name_546, 2261
	.quad case_547, name_547, 2261
	.quad case_548, name_548, 2261
	.quad case_549, name_549, 2261
	.quad case_550, name_550, 2261
	.quad case_551, name_551, 2261
	.quad case_552, name_552, 2261
	.quad case_553, name_553, 2261
	.quad case_554, name_554, 2261
	.quad case_555, name_555, 2261
	.quad case_556, name_556, 2261
	.quad case_557, name_557, 2261
	.quad case_558, name_558, 2261
	.quad case_559, name_559, 2261
	.quad case_560, name_560, 2261
	.quad case_561, name_561, 2261
	.quad case_562, name_562, 2261
	.quad case_563, name_563, 2261
	.quad case_564, name_564, 2261
	.quad case_565, name_565, 2261
	.quad case_566, name_566, 2261
	.quad case_567, name_567, 2261
	.quad case_568, name_568, 2261
	.quad case_569, name_569, 2261
	.quad case_570, name_570, 2261
	.quad case_571, name_571, 2261
	.quad case_572, name_572, 2261
	.quad case_573, name_573, 2261
	.quad case_574, name_574, 2261
	.quad case_575, name_575, 2261
	.quad case_576, name_576, 2261
	.quad case_577, name_577, 2261
	.quad case_578, name_578, 2261
	.quad case_579, name_579, 2261
	.quad case_580, name_580, 2261
	.quad case_581, name_581, 2261
	.quad case_582, name_582, 2261
	.quad case_583, name_583, 2261
	.quad case_584, name_584, 2261
	.quad case_585, name_585, 2261
	.quad case_586, name_586, 2261
	.quad case_587, name_587, 2261
	.quad case_588, name_588, 2261
	.quad case_589, name_589, 2261
	.quad case_590, name_590, 2261
	.quad case_591, name_591, 2261
	.quad case_592, name_592, 2261
	.quad case_593, name_593, 2261
	.quad case_594, name_594, 2261
	.quad case_595, name_595, 2261
	.quad case_596, name_596, 2261
	.quad case_597, name_597, 2261
	.quad case_598, name_598, 2261
	.quad case_599, name_599, 2261
	.quad case_600, name_600, 2261
	.quad case_601, name_601, 2261
	.quad case_602, name_602, 2261
	.quad case_603, name_603, 2261
	.quad case_604, name_604, 2261
	.quad case_605, name_605, 2261
	.quad case_606, name_606, 2261
	.quad case_607, name_607, 2261
	.quad case_608, name_608, 2261
	.quad case_609, name_609, 2261
	.quad case_610, name_610, 2261
	.quad case_611, name_611, 2261
	.quad case_612, name_612, 2261
	.quad case_613, name_613, 2261
	.quad case_614, name_614, 2261
	.quad case_615, name_615, 2261
	.quad case_616, name_616, 2261
	.quad case_617, name_617, 2261
	.quad case_618, name_618, 2261
	.quad case_619, name_619, 2261
	.quad case_620, name_620, 2261
	.quad case_621, name_621, 2261
	.quad case_622, name_622, 2261
	.quad case_623, name_623, 2261
	.quad case_624, name_624, 2261
	.quad case_625, name_625, 2261
	.quad case_626, name_626, 2261
	.quad case_627, name_627, 2261
	.quad case_628, name_628, 2261
	.quad case_629, name_629, 2261
	.quad case_630, name_630, 2261
	.quad case_631, name_631, 2261
	.quad case_632, name_632, 2261
	.quad case_633, name_633, 2261
	.quad case_634, name_634, 2261
	.quad case_635, name_635, 2261
	.quad case_636, name_636, 2261
	.quad case_637, name_637, 2261
	.quad case_638, name_638, 2261
	.quad case_639, name_639, 2261
	.quad case_640, name_640, 2261
	.quad case_641, name_641, 2261
	.quad case_642, name_642, 2261
	.quad case_643, name_643, 2261
	.quad case_644, name_644, 2261
	.quad case_645, name_645, 2261
	.quad case_646, name_646, 2261
	.quad case_647, name_647, 2261
	.quad case_648, name_648, 2261
	.quad case_649, name_649, 2261
	.quad case_650, name_650, 2261
	.quad case_651, name_651, 2261
	.quad case_652, name_652, 2261
	.quad case_653, name_653, 2261
	.quad case_654, name_654, 2261
	.quad case_655, name_655, 2261
	.quad case_656, name_656, 2261
	.quad case_657, name_657, 2261
	.quad case_658, name_658, 2261
	.quad case_659, name_659, 2261
	.quad case_660, name_660, 2261
	.quad case_661, name_661, 2261
	.quad case_662, name_662, 2261
	.quad case_663, name_663, 2261
	.quad case_664, name_664, 2261
	.quad case_665, name_665, 2261
	.quad case_666, name_666, 2261
	.quad case_667, name_667, 2261
	.quad case_668, name_668, 2261
	.quad case_669, name_669, 2261
	.quad case_670, name_670, 2261
	.quad case_671, name_671, 2261
	.quad case_672, name_672, 2261
	.quad case_673, name_673, 2261
	.quad case_674, name_674, 2261
	.quad case_675, name_675, 2261
	.quad case_676, name_676, 2261
	.quad case_677, name_677, 2261
	.quad case_678, name_678, 2261
	.quad case_679, name_679, 2261
	.quad case_680, name_680, 2261
	.quad case_681, name_681, 2261
	.quad case_682, name_682, 2261
	.quad case_683, name_683, 2261
	.quad case_684, name_684, 2261
	.quad case_685, name_685, 2261
	.quad case_686, name_686, 2261
	.quad case_687, name_687, 2261
	.quad case_688, name_688, 2261
	.quad case_689, name_689, 2261
	.quad case_690, name_690, 2261
	.quad case_691, name_691, 2261
	.quad case_692, name_692, 2261
	.quad case_693, name_693, 2261
	.quad case_694, name_694, 2261
	.quad case_695, name_695, 2261
	.quad case_696, name_696, 2261
	.quad case_697, name_697, 2261
	.quad case_698, name_698, 2261
	.quad case_699, name_699, 2261
	.quad case_700, name_700, 2261
	.quad case_701, name_701, 2261
	.quad case_702, name_702, 2261
	.quad case_703, name_703, 2261
	.quad case_704, name_704, 2261
	.quad case_705, name_705, 2261
	.quad case_706, name_706, 2261
	.quad case_707, name_707, 2261
	.quad case_708, name_708, 2261
	.quad case_709, name_709, 2261
	.quad case_710, name_710, 2261
	.quad case_711, name_711, 2261
	.quad case_712, name_712, 2261
	.quad case_713, name_713, 2261
	.quad case_714, name_714, 2261
	.quad case_715, name_715, 2261
	.quad case_716, name_716, 2261
	.quad case_717, name_717, 2261
	.quad case_718, name_718, 2261
	.quad case_719, name_719, 2261
	.quad case_720, name_720, 2261
	.quad case_721, name_721, 2261
	.quad case_722, name_722, 2261
	.quad case_723, name_723, 2261
	.quad case_724, name_724, 2261
	.quad case_725, name_725, 2261
	.quad case_726, name_726, 2261
	.quad case_727, name_727, 2261
	.quad case_728, name_728, 2261
	.quad case_729, name_729, 2261
	.quad case_730, name_730, 2261
	.quad case_731, name_731, 2261
	.quad case_732, name_732, 2261
	.quad case_733, name_733, 2261
	.quad case_734, name_734, 2261
	.quad case_735, name_735, 2261
	.quad case_736, name_736, 2261
	.quad case_737, name_737, 2261
	.quad case_738, name_738, 2261
	.quad case_739, name_739, 2261
	.quad case_740, name_740, 2261
	.quad case_741, name_741, 2261
	.quad case_742, name_742, 2261
	.quad case_743, name_743, 2261
	.quad case_744, name_744, 2261
	.quad case_745, name_745, 2261
	.quad case_746, name_746, 2261
	.quad case_747, name_747, 2261
	.quad case_748, name_748, 2261
	.quad case_749, name_749, 2261
	.quad case_750, name_750, 2261
	.quad case_751, name_751, 2261
	.quad case_752, name_752, 2261
	.quad case_753, name_753, 2261
	.quad case_754, name_754, 2261
	.quad case_755, name_755, 2261
	.quad case_756, name_756, 2261
	.quad case_757, name_757, 2261
	.quad case_758, name_758, 2261
	.quad case_759, name_759, 2261
	.quad case_760, name_760, 2261
	.quad case_761, name_761, 2261
	.quad case_762, name_762, 2261
	.quad case_763, name_763, 2261
	.quad case_764, name_764, 2261
	.quad case_765, name_765, 2261
	.quad case_766, name_766, 2261
	.quad case_767, name_767, 2261
	.quad case_768, name_768, 2261
	.quad case_769, name_769, 2261
	.quad case_770, name_770, 2261
	.quad case_771, name_771, 2261
	.quad case_772, name_772, 2261
	.quad case_773, name_773, 2261
	.quad case_774, name_774, 2261
	.quad case_775, name_775, 2261
	.quad case_776, name_776, 2261
	.quad case_777, name_777, 2261
	.quad case_778, name_778, 2261
	.quad case_779, name_779, 2261
	.quad case_780, name_780, 2261
	.quad case_781, name_781, 2261
	.quad case_782, name_782, 2261
	.quad case_783, name_783, 2261
	.quad case_784, name_784, 2261
	.quad case_785, name_785, 2261
	.quad case_786, name_786, 2261
	.quad case_787, name_787, 2261
	.quad case_788, name_788, 2261
	.quad case_789, name_789, 2261
	.quad case_790, name_790, 2261
	.quad case_791, name_791, 2261
	.quad case_792, name_792, 2261
	.quad case_793, name_793, 2261
	.quad case_794, name_794, 2261
	.quad case_795, name_795, 2261
	.quad case_796, name_796, 2261
	.quad case_797, name_797, 2261
	.quad case_798, name_798, 2261
	.quad case_799, name_799, 2261
	.quad case_800, name_800, 2261
	.quad case_801, name_801, 2261
	.quad case_802, name_802, 2261
	.quad case_803, name_803, 2261
	.quad case_804, name_804, 2261
	.quad case_805, name_805, 2261
	.quad case_806, name_806, 2261
	.quad case_807, name_807, 2261
	.quad case_808, name_808, 2261
	.quad case_809, name_809, 2261
	.quad case_810, name_810, 2261
	.quad case_811, name_811, 2261
	.quad case_812, name_812, 2261
	.quad case_813, name_813, 2261
	.quad case_814, name_814, 2261
	.quad case_815, name_815, 2261
	.quad case_816, name_816, 2261
	.quad case_817, name_817, 2261
	.quad case_818, name_818, 2261
	.quad case_819, name_819, 2261
	.quad case_820, name_820, 2261
	.quad case_821, name_821, 2261
	.quad case_822, name_822, 2261
	.quad case_823, name_823, 2261
	.quad case_824, name_824, 2261
	.quad case_825, name_825, 2261
	.quad case_826, name_826, 2261
	.quad case_827, name_827, 2261
	.quad case_828, name_828, 2261
	.quad case_829, name_829, 2261
	.quad case_830, name_830, 2261
	.quad case_831, name_831, 2261
	.quad case_832, name_832, 2261
	.quad case_833, name_833, 2261
	.quad case_834, name_834, 2261
	.quad case_835, name_835, 2261
	.quad case_836, name_836, 2261
	.quad case_837, name_837, 2261
	.quad case_838, name_838, 2261
	.quad case_839, name_839, 2261
	.quad case_840, name_840, 2261
	.quad case_841, name_841, 2261
	.quad case_842, name_842, 2261
	.quad case_843, name_843, 2261
	.quad case_844, name_844, 2261
	.quad case_845, name_845, 2261
	.quad case_846, name_846, 2261
	.quad case_847, name_847, 2261
	.quad case_848, name_848, 2261
	.quad case_849, name_849, 2261
	.quad case_850, name_850, 2261
	.quad case_851, name_851, 2261
	.quad case_852, name_852, 2261
	.quad case_853, name_853, 2261
	.quad case_854, name_854, 2261
	.quad case_855, name_855, 2261
	.quad case_856, name_856, 2261
	.quad case_857, name_857, 2261
	.quad case_858, name_858, 2261
	.quad case_859, name_859, 2261
	.quad case_860, name_860, 2261
	.quad case_861, name_861, 2261
	.quad case_862, name_862, 2261
	.quad case_863, name_863, 2261
	.quad case_864, name_864, 2261
	.quad case_865, name_865, 2261
	.quad case_866, name_866, 2261
	.quad case_867, name_867, 2261
	.quad case_868, name_868, 2261
	.quad case_869, name_869, 2261
	.quad case_870, name_870, 2261
	.quad case_871, name_871, 2261
	.quad case_872, name_872, 2261
	.quad case_873, name_873, 2261
	.quad case_874, name_874, 2261
	.quad case_875, name_875, 2261
	.quad case_876, name_876, 2261
	.quad case_877, name_877, 2261
	.quad case_878, name_878, 2261
	.quad case_879, name_879, 2261
	.quad case_880, name_880, 2261
	.quad case_881, name_881, 2261
	.quad case_882, name_882, 2261
	.quad case_883, name_883, 2261
	.quad case_884, name_884, 2261
	.quad case_885, name_885, 2261
	.quad case_886, name_886, 2261
	.quad case_887, name_887, 2261
	.quad case_888, name_888, 2261
	.quad case_889, name_889, 2261
	.quad case_890, name_890, 2261
	.quad case_891, name_891, 2261
	.quad case_892, name_892, 2261
	.quad case_893, name_893, 2261
	.quad case_894, name_894, 2261
	.quad case_895, name_895, 2261
	.quad case_896, name_896, 2261
	.quad case_897, name_897, 2261
	.quad case_898, name_898, 2261
	.quad case_899, name_899, 2261
	.quad case_900, name_900, 2261
	.quad case_901, name_901, 2261
	.quad case_902, name_902, 2261
	.quad case_903, name_903, 2261
	.quad case_904, name_904, 2261
	.quad case_905, name_905, 2261
	.quad case_906, name_906, 2261
	.quad case_907, name_907, 2261
	.quad case_908, name_908, 2261
	.quad case_909, name_909, 2261
	.quad case_910, name_910, 2261
	.quad case_911, name_911, 2261
	.quad case_912, name_912, 2261
	.quad case_913, name_913, 2261
	.quad case_914, name_914, 2261
	.quad case_915, name_915, 2261
	.quad case_916, name_916, 2261
	.quad case_917, name_917, 2261
	.quad case_918, name_918, 2261
	.quad case_919, name_919, 2261
	.quad case_920, name_920, 2261
	.quad case_921, name_921, 2261
	.quad case_922, name_922, 2261
	.quad case_923, name_923, 2261
	.quad case_924, name_924, 2261
	.quad case_925, name_925, 2261
	.quad case_926, name_926, 2261
	.quad case_927, name_927, 2261
	.quad case_928, name_928, 2261
	.quad case_929, name_929, 2261
	.quad case_930, name_930, 2261
	.quad case_931, name_931, 2261
	.quad case_932, name_932, 2261
	.quad case_933, name_933, 2261
	.quad case_934, name_934, 2261
	.quad case_935, name_935, 2261
	.quad case_936, name_936, 2261
	.quad case_937, name_937, 2261
	.quad case_938, name_938, 2261
	.quad case_939, name_939, 2261
	.quad case_940, name_940, 2261
	.quad case_941, name_941, 2261
	.quad case_942, name_942, 2261
	.quad case_943, name_943, 2261
	.quad case_944, name_944, 2261
	.quad case_945, name_945, 2261
	.quad case_946, name_946, 2261
	.quad case_947, name_947, 2261
	.quad case_948, name_948, 2261
	.quad case_949, name_949, 2261
	.quad case_950, name_950, 2261
	.quad case_951, name_951, 2261
	.quad case_952, name_952, 2261
	.quad case_953, name_953, 2261
	.quad case_954, name_954, 2261
	.quad case_955, name_955, 2261
	.quad case_956, name_956, 2261
	.quad case_957, name_957, 2261
	.quad case_958, name_958, 2261
	.quad case_959, name_959, 2261
	.quad case_960, name_960, 2261
	.quad case_961, name_961, 2261
	.quad case_962, name_962, 2261
	.quad case_963, name_963, 2261
	.quad case_964, name_964, 2261
	.quad case_965, name_965, 2261
	.quad case_966, name_966, 2261
	.quad case_967, name_967, 2261
	.quad case_968, name_968, 2261
	.quad case_969, name_969, 2261
	.quad case_970, name_970, 2261
	.quad case_971, name_971, 2261
	.quad case_972, name_972, 2261
	.quad case_973, name_973, 2261
	.quad case_974, name_974, 2261
	.quad case_975, name_975, 2261
	.quad case_976, name_976, 2261
	.quad case_977, name_977, 2261
	.quad case_978, name_978, 2261
	.quad case_979, name_979, 2261
	.quad case_980, name_980, 2261
	.quad case_981, name_981, 2261
	.quad case_982, name_982, 2261
	.quad case_983, name_983, 2261
	.quad case_984, name_984, 2261
	.quad case_985, name_985, 2261
	.quad case_986, name_986, 2261
	.quad case_987, name_987, 2261
	.quad case_988, name_988, 2261
	.quad case_989, name_989, 2261
	.quad case_990, name_990, 2261
	.quad case_991, name_991, 2261
	.quad case_992, name_992, 2261
	.quad case_993, name_993, 2261
	.quad case_994, name_994, 2261
	.quad case_995, name_995, 2261
	.quad case_996, name_996, 2261
	.quad case_997, name_997, 2261
	.quad case_998, name_998, 2261
	.quad case_999, name_999, 2261
	.quad case_1000, name_1000, 2261
	.quad case_1001, name_1001, 2261
	.quad case_1002, name_1002, 2261
	.quad case_1003, name_1003, 2261
	.quad case_1004, name_1004, 2261
	.quad case_1005, name_1005, 2261
	.quad case_1006, name_1006, 2261
	.quad case_1007, name_1007, 2261
	.quad case_1008, name_1008, 2261
	.quad case_1009, name_1009, 2261
	.quad case_1010, name_1010, 2261
	.quad case_1011, name_1011, 2261
	.quad case_1012, name_1012, 2261
	.quad case_1013, name_1013, 2261
	.quad case_1014, name_1014, 2261
	.quad case_1015, name_1015, 2261
	.quad case_1016, name_1016, 2261
	.quad case_1017, name_1017, 2261
	.quad case_1018, name_1018, 2261
	.quad case_1019, name_1019, 2261
	.quad case_1020, name_1020, 2261
	.quad case_1021, name_1021, 2261
	.quad case_1022, name_1022, 2261
	.quad case_1023, name_1023, 2261
	.quad case_1024, name_1024, 2261
	.quad case_1025, name_1025, 2261
	.quad case_1026, name_1026, 2261
	.quad case_1027, name_1027, 2261
	.quad case_1028, name_1028, 2261
	.quad case_1029, name_1029, 2261
	.quad case_1030, name_1030, 2261
	.quad case_1031, name_1031, 2261
	.quad case_1032, name_1032, 2261
	.quad case_1033, name_1033, 2261
	.quad case_1034, name_1034, 2261
	.quad case_1035, name_1035, 2261
	.quad case_1036, name_1036, 2261
	.quad case_1037, name_1037, 2261
	.quad case_1038, name_1038, 2261
	.quad case_1039, name_1039, 2261
	.quad case_1040, name_1040, 2261
	.quad case_1041, name_1041, 2261
	.quad case_1042, name_1042, 2261
	.quad case_1043, name_1043, 2261
	.quad case_1044, name_1044, 2261
	.quad case_1045, name_1045, 2261
	.quad case_1046, name_1046, 2261
	.quad case_1047, name_1047, 2261
	.quad case_1048, name_1048, 2261
	.quad case_1049, name_1049, 2261
	.quad case_1050, name_1050, 2261
	.quad case_1051, name_1051, 2261
	.quad case_1052, name_1052, 2261
	.quad case_1053, name_1053, 2261
	.quad case_1054, name_1054, 2261
	.quad case_1055, name_1055, 2261
	.quad case_1056, name_1056, 2261
	.quad case_1057, name_1057, 2261
	.quad case_1058, name_1058, 2261
	.quad case_1059, name_1059, 2261
	.quad case_1060, name_1060, 2261
	.quad case_1061, name_1061, 2261
	.quad case_1062, name_1062, 2261
	.quad case_1063, name_1063, 2261
	.quad case_1064, name_1064, 2261
	.quad case_1065, name_1065, 2261
	.quad case_1066, name_1066, 2261
	.quad case_1067, name_1067, 2261
	.quad case_1068, name_1068, 2261
	.quad case_1069, name_1069, 2261
	.quad case_1070, name_1070, 2261
	.quad case_1071, name_1071, 2261
	.quad case_1072, name_1072, 2261
	.quad case_1073, name_1073, 2261
	.quad case_1074, name_1074, 2261
	.quad case_1075, name_1075, 2261
	.quad case_1076, name_1076, 2261
	.quad case_1077, name_1077, 2261
	.quad case_1078, name_1078, 2261
	.quad case_1079, name_1079, 2261
	.quad case_1080, name_1080, 2261
	.quad case_1081, name_1081, 2261
	.quad case_1082, name_1082, 2261
	.quad case_1083, name_1083, 2261
	.quad case_1084, name_1084, 2261
	.quad case_1085, name_1085, 2261
	.quad case_1086, name_1086, 2261
	.quad case_1087, name_1087, 2261
	.quad case_1088, name_1088, 2261
	.quad case_1089, name_1089, 2261
	.quad case_1090, name_1090, 2261
	.quad case_1091, name_1091, 2261
	.quad case_1092, name_1092, 2261
	.quad case_1093, name_1093, 2261
	.quad case_1094, name_1094, 2261
	.quad case_1095, name_1095, 2261
	.quad case_1096, name_1096, 2261
	.quad case_1097, name_1097, 2261
	.quad case_1098, name_1098, 2261
	.quad case_1099, name_1099, 2261
	.quad case_1100, name_1100, 2261
	.quad case_1101, name_1101, 2261
	.quad case_1102, name_1102, 2261
	.quad case_1103, name_1103, 2261
	.quad case_1104, name_1104, 2261
	.quad case_1105, name_1105, 2261
	.quad case_1106, name_1106, 2261
	.quad case_1107, name_1107, 2261
	.quad case_1108, name_1108, 2261
	.quad case_1109, name_1109, 2261
	.quad case_1110, name_1110, 2261
	.quad case_1111, name_1111, 2261
	.quad case_1112, name_1112, 2261
	.quad case_1113, name_1113, 2261
	.quad case_1114, name_1114, 2261
	.quad case_1115, name_1115, 2261
	.quad case_1116, name_1116, 2261
	.quad case_1117, name_1117, 2261
	.quad case_1118, name_1118, 2261
	.quad case_1119, name_1119, 2261
	.quad case_1120, name_1120, 2261
	.quad case_1121, name_1121, 2261
	.quad case_1122, name_1122, 2261
	.quad case_1123, name_1123, 2261
	.quad case_1124, name_1124, 2261
	.quad case_1125, name_1125, 2261
	.quad case_1126, name_1126, 2261
	.quad case_1127, name_1127, 2261
	.quad case_1128, name_1128, 2261
	.quad case_1129, name_1129, 2261
	.quad case_1130, name_1130, 2261
	.quad case_1131, name_1131, 2261
	.quad case_1132, name_1132, 2261
	.quad case_1133, name_1133, 2261
	.quad case_1134, name_1134, 2261
	.quad case_1135, name_1135, 2261
	.quad case_1136, name_1136, 2261
	.quad case_1137, name_1137, 2261
	.quad case_1138, name_1138, 2261
	.quad case_1139, name_1139, 2261
	.quad case_1140, name_1140, 2261
	.quad case_1141, name_1141, 2261
	.quad case_1142, name_1142, 2261
	.quad case_1143, name_1143, 2261
	.quad case_1144, name_1144, 2261
	.quad case_1145, name_1145, 2261
	.quad case_1146, name_1146, 2261
	.quad case_1147, name_1147, 2261
	.quad case_1148, name_1148, 2261
	.quad case_1149, name_1149, 2261
	.quad case_1150, name_1150, 2261
	.quad case_1151, name_1151, 2261
	.quad case_1152, name_1152, 2261
	.quad case_1153, name_1153, 2261
	.quad case_1154, name_1154, 2261
	.quad case_1155, name_1155, 2261
	.quad case_1156, name_1156, 2261
	.quad case_1157, name_1157, 2261
	.quad case_1158, name_1158, 2261
	.quad case_1159, name_1159, 2261
	.quad case_1160, name_1160, 2261
	.quad case_1161, name_1161, 2261
	.quad case_1162, name_1162, 2261
	.quad case_1163, name_1163, 2261
	.quad case_1164, name_1164, 2261
	.quad case_1165, name_1165, 2261
	.quad case_1166, name_1166, 2261
	.quad case_1167, name_1167, 2261
	.quad case_1168, name_1168, 2261
	.quad case_1169, name_1169, 2261
	.quad case_1170, name_1170, 2261
	.quad case_1171, name_1171, 2261
	.quad case_1172, name_1172, 2261
	.quad case_1173, name_1173, 2261
	.quad case_1174, name_1174, 2261
	.quad case_1175, name_1175, 2261
	.quad case_1176, name_1176, 2261
	.quad case_1177, name_1177, 2261
	.quad case_1178, name_1178, 2261
	.quad case_1179, name_1179, 2261
	.quad case_1180, name_1180, 2261
	.quad case_1181, name_1181, 2261
	.quad case_1182, name_1182, 2261
	.quad case_1183, name_1183, 2261
	.quad case_1184, name_1184, 2261
	.quad case_1185, name_1185, 2261
	.quad case_1186, name_1186, 2261
	.quad case_1187, name_1187, 2261
	.quad case_1188, name_1188, 2261
	.quad case_1189, name_1189, 2261
	.quad case_1190, name_1190, 2261
	.quad case_1191, name_1191, 2261
	.quad case_1192, name_1192, 2261
	.quad case_1193, name_1193, 2261
	.quad case_1194, name_1194, 2261
	.quad case_1195, name_1195, 2261
	.quad case_1196, name_1196, 2261
	.quad case_1197, name_1197, 2261
	.quad case_1198, name_1198, 2261
	.quad case_1199, name_1199, 2261
	.quad case_1200, name_1200, 2261
	.quad case_1201, name_1201, 2261
	.quad case_1202, name_1202, 2261
	.quad case_1203, name_1203, 2261
	.quad case_1204, name_1204, 2261
	.quad case_1205, name_1205, 2261
	.quad case_1206, name_1206, 2261
	.quad case_1207, name_1207, 2261
	.quad case_1208, name_1208, 2261
	.quad case_1209, name_1209, 2261
	.quad case_1210, name_1210, 2261
	.quad case_1211, name_1211, 2261
	.quad case_1212, name_1212, 2261
	.quad case_1213, name_1213, 2261
	.quad case_1214, name_1214, 2261
	.quad case_1215, name_1215, 2261
	.quad case_1216, name_1216, 2261
	.quad case_1217, name_1217, 2261
	.quad case_1218, name_1218, 2261
	.quad case_1219, name_1219, 2261
	.quad case_1220, name_1220, 2261
	.quad case_1221, name_1221, 2261
	.quad case_1222, name_1222, 2261
	.quad case_1223, name_1223, 2261
	.quad case_1224, name_1224, 2261
	.quad case_1225, name_1225, 2261
	.quad case_1226, name_1226, 2261
	.quad case_1227, name_1227, 2261
	.quad case_1228, name_1228, 2261
	.quad case_1229, name_1229, 2261
	.quad case_1230, name_1230, 2261
	.quad case_1231, name_1231, 2261
	.quad case_1232, name_1232, 2261
	.quad case_1233, name_1233, 2261
	.quad case_1234, name_1234, 2261
	.quad case_1235, name_1235, 2261
	.quad case_1236, name_1236, 2261
	.quad case_1237, name_1237, 2261
	.quad case_1238, name_1238, 2261
	.quad case_1239, name_1239, 2261
	.quad case_1240, name_1240, 2261
	.quad case_1241, name_1241, 2261
	.quad case_1242, name_1242, 2261
	.quad case_1243, name_1243, 2261
	.quad case_1244, name_1244, 2261
	.quad case_1245, name_1245, 2261
	.quad case_1246, name_1246, 2261
	.quad case_1247, name_1247, 2261
	.quad case_1248, name_1248, 2261
	.quad case_1249, name_1249, 2261
	.quad case_1250, name_1250, 2261
	.quad case_1251, name_1251, 2261
	.quad case_1252, name_1252, 2261
	.quad case_1253, name_1253, 2261
	.quad case_1254, name_1254, 2261
	.quad case_1255, name_1255, 2261
	.quad case_1256, name_1256, 2261
	.quad case_1257, name_1257, 2261
	.quad case_1258, name_1258, 2261
	.quad case_1259, name_1259, 2261
	.quad case_1260, name_1260, 2261
	.quad case_1261, name_1261, 2261
	.quad case_1262, name_1262, 2261
	.quad case_1263, name_1263, 2261
	.quad case_1264, name_1264, 2261
	.quad case_1265, name_1265, 2241
	.quad case_1266, name_1266, 2241
	.quad case_1267, name_1267, 64
	.quad case_1268, name_1268, 2241
	.quad case_1269, name_1269, 2177
	.quad case_1270, name_1270, 2241
	.quad case_1271, name_1271, 2241
	.quad case_1272, name_1272, 0
	.quad case_1273, name_1273, 0
	.quad case_1274, name_1274, 0
	.quad case_1275, name_1275, 0
	.quad case_1276, name_1276, 0
	.quad case_1277, name_1277, 0
	.quad case_1278, name_1278, 0
	.quad case_1279, name_1279, 0
	.quad case_1280, name_1280, 0
	.quad case_1281, name_1281, 0
	.quad case_1282, name_1282, 0
	.quad case_1283, name_1283, 65
	.quad case_1284, name_1284, 65
	.quad case_1285, name_1285, 65
	.quad case_1286, name_1286, 65
	.quad case_1287, name_1287, 2261
	.quad case_1288, name_1288, 0
	.quad case_1289, name_1289, 0
	.quad case_1290, name_1290, 0
	.quad case_1291, name_1291, 0
	.quad case_1292, name_1292, 0
	.quad case_1293, name_1293, 0
	.quad case_1294, name_1294, 0
	.quad case_1295, name_1295, 64
	.quad case_1296, name_1296, 65
	.quad case_1297, name_1297, 65
	.quad case_1298, name_1298, 65
	.quad case_1299, name_1299, 65
	.quad case_1300, name_1300, 65
	.quad case_1301, name_1301, 65
	.quad case_1302, name_1302, 2241
	.quad case_1303, name_1303, 2241
	.quad case_1304, name_1304, 2177
	.quad case_1305, name_1305, 0
	.quad case_1306, name_1306, 0
	.quad case_1307, name_1307, 0
	.quad case_1308, name_1308, 0
	.quad case_1309, name_1309, 2241
	.quad case_1310, name_1310, 2241
	.quad case_1311, name_1311, 0
	.quad case_1312, name_1312, 2261
	.quad case_1313, name_1313, 0
	.quad case_1314, name_1314, 2241
	.quad case_1315, name_1315, 2241
	.quad case_1316, name_1316, 2241
	.quad case_1317, name_1317, 2241
	.quad case_1318, name_1318, 2241
	.quad case_1319, name_1319, 2241
	.quad case_1320, name_1320, 2241
	.quad case_1321, name_1321, 2241
	.quad case_1322, name_1322, 2241
	.quad case_1323, name_1323, 2241
	.quad case_1324, name_1324, 2241
	.quad case_1325, name_1325, 2261
	.quad case_1326, name_1326, 2261
	.quad case_1327, name_1327, 2261
	.quad case_1328, name_1328, 2261
	.quad case_1329, name_1329, 2261
	.quad case_1330, name_1330, 2261
	.quad case_1331, name_1331, 2261
	.quad 0, 0, 0
