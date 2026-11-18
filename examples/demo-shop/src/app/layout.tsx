export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <script async src="https://www.googletagmanager.com/gtag/js?id=G-DEMO000000"></script>
        <script
          dangerouslySetInnerHTML={{
            __html: `!function(f,b,e,v){/* Meta pixel */}(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');`,
          }}
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
