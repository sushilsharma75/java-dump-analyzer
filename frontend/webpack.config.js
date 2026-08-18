const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');

module.exports = (env, argv) => {
  const isProd = argv.mode === 'production';

  return {
    entry: './src/main.jsx',

    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: isProd ? 'assets/[name].[contenthash:8].js' : 'assets/[name].js',
      publicPath: '/',
      clean: true,
    },

    resolve: {
      extensions: ['.js', '.jsx'],
    },

    module: {
      rules: [
        {
          test: /\.jsx?$/,
          exclude: /node_modules/,
          use: {
            loader: 'babel-loader',
            options: {
              presets: [
                ['@babel/preset-env', { targets: { esmodules: true } }],
                ['@babel/preset-react', { runtime: 'automatic' }],
              ],
              cacheDirectory: true,
            },
          },
        },
        {
          test: /\.css$/,
          use: [
            isProd ? MiniCssExtractPlugin.loader : 'style-loader',
            'css-loader',
          ],
        },
      ],
    },

    plugins: [
      new HtmlWebpackPlugin({
        template: './public/index.html',
        inject: 'body',
      }),
      ...(isProd
        ? [new MiniCssExtractPlugin({
            filename: 'assets/[name].[contenthash:8].css',
          })]
        : []),
    ],

    devServer: {
      port: 5173,
      historyApiFallback: true,
      hot: true,
      open: false,
      static: {
        directory: path.join(__dirname, 'public'),
      },
      // Proxy /api/* to the FastAPI backend, same as the old Vite config did.
      proxy: [
        {
          context: ['/api'],
          target: 'http://localhost:8000',
          changeOrigin: true,
        },
      ],
    },

    devtool: isProd ? 'source-map' : 'eval-cheap-module-source-map',

    performance: {
      // The build is genuinely a single bundle; loosen the warning thresholds.
      maxEntrypointSize: 512000,
      maxAssetSize: 512000,
    },
  };
};
