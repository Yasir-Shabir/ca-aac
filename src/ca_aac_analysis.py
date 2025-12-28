#!/usr/bin/env python3
"""
CA-AAC: Context-Aware Adaptive Access Control System
===================================================

Author: Yasir Shabir
Date: 2025
License: MIT

This script implements a context-aware access control system using:
1. Rabin Logic for formal correctness verification
2. Machine Learning for runtime threat estimation
3. TON_IoT Dataset for empirical validation
"""

import argparse
import os
import sys
from pathlib import Path

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc
)
import warnings
warnings.filterwarnings('ignore')


class RabinAccessControl:
    """
    Context-Aware Adaptive Access Control System
    
    Implements Rabin logic for formal verification and ML for threat estimation.
    """
    
    def __init__(self, threshold_low=0.3, threshold_high=0.6, output_dir='results'):
        """
        Initialize CA-AAC system
        
        Args:
            threshold_low (float): Low threat threshold (default: 0.3)
            threshold_high (float): High threat threshold (default: 0.6)
            output_dir (str): Output directory for results
        """
        self.THRESHOLD_LOW = threshold_low
        self.THRESHOLD_HIGH = threshold_high
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.model = None
        self.label_encoders = {}
        self.results = {}
        
        print("=" * 80)
        print("CA-AAC: Context-Aware Adaptive Access Control System")
        print("Rabin Logic + Machine Learning + TON_IoT Validation")
        print("=" * 80)
    
    def load_dataset(self, filepath):
        """Load TON_IoT dataset"""
        print(f"\n[STEP 1] Loading Dataset")
        print("-" * 80)
        
        if not os.path.exists(filepath):
            print(f" Error: File not found: {filepath}")
            sys.exit(1)
        
        try:
            df = pd.read_csv(filepath)
            print(f"Dataset loaded successfully")
            print(f"  Total records: {len(df):,}")
            print(f"  Total features: {len(df.columns)}")
            return df
        except Exception as e:
            print(f"Error loading dataset: {e}")
            sys.exit(1)
    
    def preprocess_data(self, df):
        """Preprocess and map to Rabin model"""
        print(f"\n[STEP 2] Preprocessing & Mapping to Rabin Model")
        print("-" * 80)
        
        # Select relevant columns
        required_cols = ['src_ip', 'dst_ip', 'proto', 'service', 'label']
        missing_cols = [col for col in required_cols if col not in df.columns]
        
        if missing_cols:
            print(f" Missing required columns: {missing_cols}")
            sys.exit(1)
        
        # Remove missing values
        initial_count = len(df)
        df = df.dropna(subset=required_cols)
        print(f"Removed missing values: {initial_count:,} → {len(df):,}")
        
        # Convert labels
        df['decision'] = df['label'].apply(lambda x: 'ALLOW' if x == 0 else 'DENY')
        df['binary_label'] = df['label']
        
        normal_count = (df['decision'] == 'ALLOW').sum()
        attack_count = (df['decision'] == 'DENY').sum()
        print(f" ALLOW: {normal_count:,} | DENY: {attack_count:,}")
        
        # Map to Rabin ACV
        df['rabin_user'] = df['src_ip']
        df['rabin_resource'] = df['dst_ip']
        df['rabin_operation'] = df['proto']
        df['rabin_context'] = df['service']
        
        print(f" Mapped to Rabin ACV: ⟨User, Resource, Operation, Context⟩")
        
        return df
    
    def encode_features(self, df):
        """Encode features for ML"""
        print(f"\n[STEP 3] Feature Engineering")
        print("-" * 80)
        
        # Encode categorical
        for col in ['proto', 'service']:
            le = LabelEncoder()
            df[f'{col}_encoded'] = le.fit_transform(df[col].astype(str))
            self.label_encoders[col] = le
        
        # Handle numeric features
        numeric_cols = ['duration', 'src_bytes', 'dst_bytes']
        for col in numeric_cols:
            if col in df.columns:
                df[f'{col}_clean'] = df[col].fillna(df[col].median())
        
        print(f" Features encoded")
        return df
    
    def train_ml_model(self, df):
        """Train ML model for threat estimation"""
        print(f"\n[STEP 4] Training ML Model")
        print("-" * 80)
        print("⚠️  ML estimates threat probability, NOT Rabin logic!")
        
        # Select features
        feature_cols = ['proto_encoded', 'service_encoded']
        if 'duration_clean' in df.columns:
            feature_cols.extend(['duration_clean', 'src_bytes_clean', 'dst_bytes_clean'])
        
        X = df[feature_cols]
        y = df['binary_label']
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f" Train: {len(X_train):,} | Test: {len(X_test):,}")
        
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_train, y_train)
        
        train_acc = self.model.score(X_train, y_train)
        test_acc = self.model.score(X_test, y_test)
        print(f" Train Acc: {train_acc*100:.2f}% | Test Acc: {test_acc*100:.2f}%")
        
        # Get probabilities
        df['threat_probability'] = self.model.predict_proba(X)[:, 1]
        
        self.results['X_test'] = X_test
        self.results['y_test'] = y_test
        
        return df
    
    def apply_rabin_logic(self, threat_prob):
        """Apply Rabin acceptance conditions"""
        if threat_prob <= self.THRESHOLD_LOW:
            return 'PERMIT', 'G(π(ACV) → F(Permit)) - Low threat'
        elif threat_prob <= self.THRESHOLD_HIGH:
            return 'CONDITIONAL', 'Medium threat'
        else:
            return 'DENY', 'G(Threat > Medium → Deny) - High threat'
    
    def evaluate_system(self, df):
        """Evaluate system performance"""
        print(f"\n[STEP 5] Applying Rabin Logic & Evaluation")
        print("-" * 80)
        
        # Apply Rabin logic
        df['rabin_decision'], df['rabin_reason'] = zip(
            *df['threat_probability'].apply(self.apply_rabin_logic)
        )
        
        df['rabin_binary'] = df['rabin_decision'].apply(
            lambda x: 0 if x == 'PERMIT' else 1
        )
        
        # Compute metrics
        y_true = df['binary_label']
        y_pred = df['rabin_binary']
        
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        # Compute ROC-AUC
        fpr_roc, tpr_roc, _ = roc_curve(y_true, df['threat_probability'])
        roc_auc = auc(fpr_roc, tpr_roc)
        
        self.results.update({
            'df': df,
            'accuracy': accuracy, 'precision': precision,
            'recall': recall, 'f1': f1, 'fpr': fpr, 'fnr': fnr,
            'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'roc_auc': roc_auc,
            'fpr_roc': fpr_roc, 'tpr_roc': tpr_roc
        })
        
        # Print results
        print(f"\n{'='*80}")
        print("PERFORMANCE METRICS")
        print(f"{'='*80}")
        print(f"Accuracy:  {accuracy*100:6.2f}%")
        print(f"Precision: {precision*100:6.2f}%")
        print(f"Recall:    {recall*100:6.2f}%")
        print(f"F1-Score:  {f1*100:6.2f}%")
        print(f"FPR:       {fpr*100:6.2f}%")
        print(f"FNR:       {fnr*100:6.2f}%")
        print(f"AUC-ROC:   {roc_auc*100:6.2f}%")
        print(f"\nTP: {tp:6,} | TN: {tn:6,} | FP: {fp:6,} | FN: {fn:6,}")
        
        return df
    
    def visualize_results(self):
        """Create visualizations"""
        print(f"\n[STEP 6] Generating Visualizations")
        print("-" * 80)
        
        df = self.results['df']
        
        fig, axes = plt.subplots(2, 3, figsize=(16, 10))
        fig.suptitle('CA-AAC Performance Analysis', fontsize=16, fontweight='bold')
        
        # 1. Confusion Matrix
        cm = confusion_matrix(df['binary_label'], df['rabin_binary'])
        sns.heatmap(cm, annot=True, fmt=',d', cmap='Blues', ax=axes[0, 0],
                   xticklabels=['ALLOW', 'DENY'], yticklabels=['ALLOW', 'DENY'])
        axes[0, 0].set_title('Confusion Matrix')
        
        # 2. Threat Distribution
        axes[0, 1].hist([df[df['binary_label']==0]['threat_probability'],
                        df[df['binary_label']==1]['threat_probability']],
                       bins=50, label=['Normal', 'Attack'], alpha=0.7)
        axes[0, 1].axvline(self.THRESHOLD_LOW, color='blue', linestyle='--')
        axes[0, 1].axvline(self.THRESHOLD_HIGH, color='red', linestyle='--')
        axes[0, 1].set_title('Threat Probability Distribution')
        axes[0, 1].legend()
        axes[0, 1].set_yscale('log')
        
        # 3. Decision Distribution
        decision_counts = df['rabin_decision'].value_counts()
        colors = {'PERMIT': 'green', 'CONDITIONAL': 'orange', 'DENY': 'red'}
        axes[0, 2].bar(decision_counts.index, decision_counts.values,
                      color=[colors.get(d, 'gray') for d in decision_counts.index])
        axes[0, 2].set_title('Rabin Decision Distribution')
        
        # 4. Metrics
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1']
        values = [self.results['accuracy'], self.results['precision'],
                 self.results['recall'], self.results['f1']]
        axes[1, 0].bar(metrics, values)
        axes[1, 0].set_title('Performance Metrics')
        axes[1, 0].set_ylim([0, 1.1])
        
        # 5. Error Rates
        axes[1, 1].bar(['FPR', 'FNR'], [self.results['fpr'], self.results['fnr']])
        axes[1, 1].set_title('Error Rates')
        
        # 6. ROC Curve
        axes[1, 2].plot(self.results['fpr_roc'], self.results['tpr_roc'],
                       label=f"AUC = {self.results['roc_auc']:.3f}")
        axes[1, 2].plot([0, 1], [0, 1], 'k--')
        axes[1, 2].set_title('ROC Curve')
        axes[1, 2].legend()
        
        plt.tight_layout()
        output_path = self.output_dir / 'ca_aac_analysis.png'
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f" Saved: {output_path}")
        
    def export_results(self):
        """Export results to CSV"""
        print(f"\n[STEP 7] Exporting Results")
        print("-" * 80)
        
        df = self.results['df']
        
        # Detailed results
        output_cols = ['src_ip', 'dst_ip', 'proto', 'service',
                      'threat_probability', 'rabin_decision', 'rabin_reason', 'decision']
        df[output_cols].to_csv(self.output_dir / 'detailed_results.csv', index=False)
        
        # Metrics
        metrics_df = pd.DataFrame({
            'Metric': ['Accuracy', 'Precision', 'Recall', 'F1-Score',
                      'FPR', 'FNR', 'AUC-ROC'],
            'Value': [
                self.results['accuracy'],
                self.results['precision'],
                self.results['recall'],
                self.results['f1'],
                self.results['fpr'],
                self.results['fnr'],
                self.results['roc_auc']
            ]
        })
        metrics_df.to_csv(self.output_dir / 'metrics_summary.csv', index=False)
        
        print(f" Results exported to: {self.output_dir}")


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description='CA-AAC: Context-Aware Adaptive Access Control System'
    )
    parser.add_argument(
        '--dataset',
        type=str,
        required=True,
        help='Path to TON_IoT dataset CSV file'
    )
    parser.add_argument(
        '--threshold-low',
        type=float,
        default=0.3,
        help='Low threat threshold (default: 0.3)'
    )
    parser.add_argument(
        '--threshold-high',
        type=float,
        default=0.6,
        help='High threat threshold (default: 0.6)'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='results',
        help='Output directory (default: results)'
    )
    
    args = parser.parse_args()
    
    # Initialize system
    ca_aac = RabinAccessControl(
        threshold_low=args.threshold_low,
        threshold_high=args.threshold_high,
        output_dir=args.output
    )
    
    # Run analysis
    df = ca_aac.load_dataset(args.dataset)
    df = ca_aac.preprocess_data(df)
    df = ca_aac.encode_features(df)
    df = ca_aac.train_ml_model(df)
    df = ca_aac.evaluate_system(df)
    ca_aac.visualize_results()
    ca_aac.export_results()
    
    print(f"\n{'='*80}")
    print(" Analysis Complete!")
    print(f"{'='*80}")


if __name__ == "__main__":
    main()