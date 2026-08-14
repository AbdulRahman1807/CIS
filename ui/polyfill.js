import util from 'node:util';
if (!util.styleText) {
  util.styleText = (format, text) => text;
}
