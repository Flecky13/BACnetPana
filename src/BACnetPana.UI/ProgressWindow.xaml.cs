using System.Windows;
using System.Windows.Threading;

namespace bacneTPana.UI
{
    public partial class ProgressWindow : Window
    {
        private bool _isCancelled = false;

        public bool IsCancelled => _isCancelled;

        public ProgressWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Aktualisiert die Progressbar und Texte
        /// </summary>
        /// <param name="phaseInfo">z.B. "Phase 1/2"</param>
        /// <param name="operation">z.B. "Lese Pakete mit SharpPcap..."</param>
        /// <param name="percent">Fortschritt in Prozent (0-100)</param>
        public void UpdateProgress(string phaseInfo, string operation, int percent)
        {
            Dispatcher.Invoke(() =>
            {
                PhaseInfoLabel.Text = phaseInfo;
                CurrentOperationLabel.Text = operation;
                ProgressBar.Value = Math.Min(100, Math.Max(0, percent));
                ProgressPercentLabel.Text = $"{percent} %";
            }, DispatcherPriority.Normal);
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            _isCancelled = true;
            CancelButton.IsEnabled = false;
            CurrentOperationLabel.Text = "Abbruch wird durchgeführt...";
        }

        /// <summary>
        /// Schließt das Fenster auf dem UI-Thread
        /// </summary>
        public void CloseWindow()
        {
            Dispatcher.Invoke(() =>
            {
                DialogResult = !_isCancelled;
                Close();
            });
        }
    }
}
