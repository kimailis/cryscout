import torch
import torch.nn as nn

class NonceAnomalyDetector(nn.Module):
    def __init__(self):
        super(NonceAnomalyDetector, self).__init__()
        # 438 features as seen in cryscout_worker_rs/src/main.rs
        self.fc1 = nn.Linear(438, 256)
        self.fc2 = nn.Linear(256, 128)
        self.fc3 = nn.Linear(128, 64)
        self.fc4 = nn.Linear(64, 1)
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.relu(self.fc2(x))
        x = self.relu(self.fc3(x))
        x = self.sigmoid(self.fc4(x))
        return x

def create_model():
    model = NonceAnomalyDetector()
    model.eval() # Set to evaluation mode before export
    
    # Export to ONNX with opset_version=12
    dummy_input = torch.randn(1, 438)
    torch.onnx.export(
        model, 
        dummy_input, 
        "nonce_anomaly_model.onnx", 
        verbose=False,
        opset_version=12,
        input_names=["input"],
        output_names=["output"]
    )
    print("Exported nonce_anomaly_model.onnx with opset_version 12.")

if __name__ == "__main__":
    create_model()
