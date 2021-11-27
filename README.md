# PSMFAttendance

PSMFAttendance は、Money Forward クラウド勤怠を CLI で操作するためのツールです。

[利用規約 | 会計ソフト マネーフォワード クラウド](https://biz.moneyforward.com/agreement/)

本ツールはスクレイピングにより各操作を実現しているので、Money Forward クラウド勤怠それ自体の変更により、急に期待通りに動かなくなることがあり得ます。

PowerShell v7 でのみ動作確認済みです。

Inspired from [puhitaku/mfpy](https://github.com/puhitaku/mfpy)

(恐らく日本国内にしか少ない需要もないと思われるので日本語で書く)

## インストール

### PowerShell Gallery から入手する

未。

### `Module` フォルダに配置する

この repository を PowerShell の `Module` フォルダ配下に clone してください。

`Module` フォルダは `$PSHOME\Modules` や `$HOME\Documents\PowerShell\Modules` 等です。

## できること

- 出勤・退勤の打刻

## 使い方

### 出勤・退勤

```powershell
# はじめに接続情報を登録します。現在インタラクティブ入力のみ対応。
Set-MFAuthentication

# 出勤
Send-BeginningWork
# 退勤
Send-FinishingWork
```

### 接続情報の初期化

入力した接続情報は `$env:APPDATA/krymtkts/PSMFAttendance/credential` に保存されます。
パスワードのみ Secure String として保存されます。
保存された接続情報を初期化するには、以下のコマンドを実行します。

```powershell
# 接続情報の初期化
Clear-MFAuthentication
```

## やろうとしていること

- PowerShell Gallery
- 勤怠の一覧
- 二重打刻の防止
- 休憩の打刻
- 実績の編集
