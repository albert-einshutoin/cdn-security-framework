# AWS Lambda@Edge Runtime

このディレクトリは Lambda@Edge（Origin Request）用のテンプレです。

## 使いどころ（CloudFront Functionsでは難しい領域）
- RS256 の JWT 検証（Cognito / OIDC など）
- より複雑な署名検証（HMACに加え複数鍵やkid対応など）
- Origin リクエスト直前の「最終ゲート」

## どこにアタッチする？
- `origin-request.js` → **Origin Request**

## 注意
- Lambda@Edge は Functions より重い（コールドスタート/実行時間/デプロイ手順）
- 入口遮断・軽量正規化は Functions に寄せ、Lambda@Edge は「必要時のみ」が基本

## 動作確認
- CloudFront の Behavior に Lambda@Edge を関連付け後、対象パスへアクセスしてログ確認