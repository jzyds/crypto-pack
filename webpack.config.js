const path = require("path");
const modeConfig = "production";

const optimizationConfig = {
  minimize: true,
};

const serverConfig = {
  entry: {
    node: "./src/node.ts",
  },
  module: {
    rules: [
      {
        loader: "ts-loader",
        exclude: /node_modules/,
        options: {
          configFile: "tsconfig.json",
        },
      },
    ],
  },
  optimization: optimizationConfig,
  mode: modeConfig,
  target: "node",
  resolve: {
    extensions: [".js", ".jsx", ".ts", ".tsx"],
  },
  output: {
    filename: "[name].js",
    path: path.resolve(__dirname, "lib"),
    libraryTarget: "commonjs",
  },
};

const clientConfig = {
  entry: {
    browser: "./src/browser.ts",
  },
  module: {
    rules: [
      {
        loader: "ts-loader",
        exclude: /node_modules/,
        options: {
          configFile: "tsconfig.json",
        },
      },
    ],
  },
  optimization: optimizationConfig,
  mode: modeConfig,
  resolve: {
    extensions: [".js", ".jsx", ".ts", ".tsx"],
    fallback: {
      // WEB PACK 5
      fs: false,
      webcrypto: false,
      crypto: false,
      console: false,
      process: false,
    },
  },
  target: "web",
  output: {
    filename: "[name].js",
    path: path.resolve(__dirname, "lib"),
    library: "cryptoPack",
    libraryTarget: "umd",
    globalObject: "this",
  },
  // watch: true,
};

module.exports = [serverConfig, clientConfig];
